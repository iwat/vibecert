package application

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/iwat/vibecert/internal/domain"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
	"software.sslmate.com/src/go-pkcs12"
)

var ErrCancelled = errors.New("cancelled")

type App struct {
	db             *dblib.Queries
	passwordReader PasswordReader
	fileReader     FileReader
	fileWriter     FileWriter
	confirmer      Confirmer
}

func NewApp(db *dblib.Queries, passwordReader PasswordReader, fileReader FileReader, fileWriter FileWriter, confirmer Confirmer) *App {
	return &App{
		db:             db,
		passwordReader: passwordReader,
		fileReader:     fileReader,
		fileWriter:     fileWriter,
		confirmer:      confirmer,
	}
}

// CreateCertificateRequest provides a request to create a new certificate
type CreateCertificateRequest struct {
	IssuerCertificateID    int
	SubjectKeyID           int
	CommonName             string
	CountryName            string
	StateName              string
	LocalityName           string
	OrganizationName       string
	OrganizationalUnitName string
	KeySpec                KeySpec
	ValidDays              int
	IsCA                   bool
}

type KeySpec string

const (
	KeySpecRSA2048  KeySpec = "RSA2048"
	KeySpecRSA3072  KeySpec = "RSA3072"
	KeySpecRSA4096  KeySpec = "RSA4096"
	KeySpecECDSA224 KeySpec = "ECDSA256"
	KeySpecECDSA256 KeySpec = "ECDSA384"
	KeySpecECDSA384 KeySpec = "ECDSA521"
)

func KnownKeySpecs() string {
	return strings.Join([]string{
		string(KeySpecRSA2048),
		string(KeySpecRSA3072),
		string(KeySpecRSA4096),
		string(KeySpecECDSA224),
		string(KeySpecECDSA256),
		string(KeySpecECDSA384),
	}, ", ")
}

func (k *KeySpec) Set(v string) error {
	v = strings.ToUpper(v)
	switch v {
	case string(KeySpecRSA2048):
		*k = KeySpecRSA2048
	case string(KeySpecRSA3072):
		*k = KeySpecRSA3072
	case string(KeySpecRSA4096):
		*k = KeySpecRSA4096
	case string(KeySpecECDSA224):
		*k = KeySpecECDSA224
	case string(KeySpecECDSA256):
		*k = KeySpecECDSA256
	case string(KeySpecECDSA384):
		*k = KeySpecECDSA384
	default:
		return fmt.Errorf("invalid key spec: %s", v)
	}
	return nil
}

func (k *KeySpec) String() string {
	return string(*k)
}

func (k *KeySpec) Type() string {
	return "keyspec"
}

func (k *KeySpec) Key(password []byte) (*domain.Key, error) {
	switch *k {
	case KeySpecRSA2048:
		return domain.NewRSAKey(2048, password)
	case KeySpecRSA3072:
		return domain.NewRSAKey(3072, password)
	case KeySpecRSA4096:
		return domain.NewRSAKey(4096, password)
	case KeySpecECDSA224:
		return domain.NewECDSAKey(elliptic.P224(), password)
	case KeySpecECDSA256:
		return domain.NewECDSAKey(elliptic.P256(), password)
	case KeySpecECDSA384:
		return domain.NewECDSAKey(elliptic.P384(), password)
	default:
		return nil, fmt.Errorf("invalid key spec: %s", *k)
	}
}

const SelfSignedCertificateID = -1
const NewSubjectKeyID = -1

func (app *App) Initialize(ctx context.Context) error {
	return app.db.InitializeDatabase(ctx)
}

func (app *App) CreateCertificate(ctx context.Context, req *CreateCertificateRequest) (*domain.Certificate, *domain.Key, error) {
	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	issuerKey, issuerPrivateKey, issuerCertificate, err := app.getIssuerContext(ctx, tx, req)
	if err != nil {
		return nil, nil, err
	}
	slog.Info("selected issuer", "cert", issuerCertificate, "key", issuerKey)

	var subjectKey *domain.Key
	var subjectPublicKey crypto.PublicKey
	var subjectPrivateKey domain.PrivateKey
	if issuerKey != nil && issuerKey.ID == req.SubjectKeyID {
		subjectKey = issuerKey
		subjectPublicKey = issuerPrivateKey.Public()
		subjectPrivateKey = issuerPrivateKey
	} else {
		subjectKey, subjectPublicKey, subjectPrivateKey, err = app.getSubjectKeyContext(ctx, tx, req)
		if err != nil {
			return nil, nil, err
		}
	}
	slog.Info("selected subject key", "key", subjectKey)

	if req.IssuerCertificateID == SelfSignedCertificateID {
		slog.Info("self-signed certificate, using subject key as issuer key")
		issuerPrivateKey = subjectPrivateKey
	}

	certificate, err := domain.NewCertificate(&domain.CreateCertificateRequest{
		IssuerCertificate:      issuerCertificate,
		IssuerPrivateKey:       issuerPrivateKey,
		CommonName:             req.CommonName,
		CountryName:            req.CountryName,
		StateName:              req.StateName,
		LocalityName:           req.LocalityName,
		OrganizationName:       req.OrganizationName,
		OrganizationalUnitName: req.OrganizationalUnitName,
		ValidDays:              req.ValidDays,
		IsCA:                   req.IsCA,
		PublicKey:              subjectPublicKey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// 5. Store and Commit
	if _, err = tx.CreateCertificate(ctx, certificate); err != nil {
		return nil, nil, fmt.Errorf("failed to store certificate: %v", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return certificate, subjectKey, nil
}

// getIssuerContext handles all logic for retrieving the issuer's private key and certificate.
// It abstracts away the self-signed vs. standard issuer difference.
func (app *App) getIssuerContext(ctx context.Context, tx *dblib.TransactionalQueries, req *CreateCertificateRequest) (*domain.Key, domain.PrivateKey, *domain.Certificate, error) {
	if req.IssuerCertificateID == SelfSignedCertificateID {
		slog.Debug("not selecting certificate, request is self-signed")
		if req.SubjectKeyID != NewSubjectKeyID {
			// Logic for self-signed with existing key (using subject key as issuer key)
			key, err := tx.KeyByID(ctx, req.SubjectKeyID)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to retrieve self-signed issuer key: %v", err)
			}
			issuerPrivateKey, err := app.tryDecryptPrivateKey(key, "self-signed issuer key")
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to decrypt self-signed issuer private key: %v", err)
			}
			slog.Debug("selected issuer key for self-signed certificate", "key", key)
			return key, issuerPrivateKey, nil, nil
		}
		return nil, nil, nil, nil
	}

	// Standard intermediate CA issuance
	issuerCertificate, err := tx.CertificateByID(ctx, req.IssuerCertificateID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to retrieve issuer certificate: %v", err)
	}
	slog.Debug("selected issuer certificate", "cert", issuerCertificate)

	issuerKey, err := tx.KeyByPublicKeyHash(ctx, issuerCertificate.PublicKeyHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to retrieve issuer private key: %v", err)
	}
	slog.Debug("selected issuer key", "key", issuerKey)

	issuerPrivateKey, err := app.tryDecryptPrivateKey(issuerKey, "issuer")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt issuer private key: %v", err)
	}

	return issuerKey, issuerPrivateKey, issuerCertificate, nil
}

// getSubjectKeyContext handles logic for retrieving or creating the subject's private key.
func (app *App) getSubjectKeyContext(ctx context.Context, tx *dblib.TransactionalQueries, req *CreateCertificateRequest) (*domain.Key, crypto.PublicKey, domain.PrivateKey, error) {
	if req.SubjectKeyID == NewSubjectKeyID {
		newPassword, err := app.askPasswordWithConfirmation("password for the new CA")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to ask for new password: %v", err)
		}

		subjectKey, err := req.KeySpec.Key(newPassword)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate private key: %v", err)
		}
		if _, err := tx.CreateKey(ctx, subjectKey); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to store key: %v", err)
		}
		slog.Debug("created subject key", "key", subjectKey)

		privateKey, err := subjectKey.Decrypt(newPassword)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
		}

		slog.Debug("using created subject key", "key", subjectKey)
		return subjectKey, privateKey.Public(), privateKey, nil
	}

	// Existing subject key
	subjectKey, err := tx.KeyByID(ctx, req.SubjectKeyID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get key by ID: %v", err)
	}
	slog.Debug("selected subject key", "key", subjectKey)
	subjectPrivateKey, err := app.tryDecryptPrivateKey(subjectKey, "subject key")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt subject private key: %v", err)
	}
	return subjectKey, subjectPrivateKey.Public(), subjectPrivateKey, nil
}

// ExportCertificateWithKeyToPKCS12 exports a certificate and its key to a PKCS#12 file
func (app *App) ExportCertificateWithKeyToPKCS12(ctx context.Context, id int, filename string) error {
	cert, err := app.db.CertificateByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("certificate with id %d not found", id)
		}
		return fmt.Errorf("failed to load certificate: %v", err)
	}
	slog.Info("got certificate", "cert", cert)
	key, err := app.db.KeyByPublicKeyHash(ctx, cert.PublicKeyHash)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}
	slog.Info("got associated key", "key", key)

	privateKey, err := key.Decrypt(nil)
	if err == domain.ErrEncryptedPrivateKey {
		slog.Info("key is encrypted, taking password")
		password, err := app.passwordReader.ReadPassword("Enter password for private key:")
		if err != nil {
			return fmt.Errorf("failed to read password: %v", err)
		}
		privateKey, err = key.Decrypt(password)
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %v", err)
		}
		slog.Info("key is now decrypted")
	}

	p12Password, err := app.askPasswordWithConfirmation("password for PKCS#12 file")
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	parents := app.findParents(ctx, cert)
	var x509Parents []*x509.Certificate
	for _, parent := range parents {
		x509Parents = append(x509Parents, parent.X509Cert())
	}

	slog.Info("encoding PKCS#12")
	pfxData, err := pkcs12.Legacy.Encode(privateKey, cert.X509Cert(), x509Parents, string(p12Password))
	if err != nil {
		return err
	}

	err = app.fileWriter.WriteFile(filename, pfxData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %v", err)
	}
	return nil
}

func (app *App) findParents(ctx context.Context, cert *domain.Certificate) []*domain.Certificate {
	uniqueParents := make(map[int]*domain.Certificate)
	certs := []*domain.Certificate{cert}
	for len(certs) > 0 {
		nextCert := certs[0]
		certs = certs[1:]

		immediateParents, err := app.db.CertificatesBySubjectAndSubjectKeyID(ctx, nextCert.IssuerDN, nextCert.AuthorityKeyID)
		if err != nil {
			break
		}
		for _, parent := range immediateParents {
			if _, ok := uniqueParents[parent.ID]; !ok {
				uniqueParents[parent.ID] = parent
				certs = append(certs, parent)
			}
		}
	}

	var parents []*domain.Certificate
	for _, parent := range uniqueParents {
		parents = append(parents, parent)
	}

	return parents
}

func (app *App) askPasswordWithConfirmation(label string) ([]byte, error) {
	password, err := app.passwordReader.ReadPassword("Enter " + label + ": ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}
	password2, err := app.passwordReader.ReadPassword("Confirm " + label + ": ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}
	if !bytes.Equal(password, password2) {
		return nil, fmt.Errorf("passwords do not match")
	}
	return []byte(password), nil
}

func (app *App) tryDecryptPrivateKey(key *domain.Key, label string) (domain.PrivateKey, error) {
	privateKey, err := key.Decrypt(nil)
	if err == nil {
		return privateKey, nil
	}
	if err != domain.ErrEncryptedPrivateKey {
		return nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}
	password, err := app.passwordReader.ReadPassword("Enter password for " + label + ": ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}
	return key.Decrypt(password)
}

// PasswordReader interface for abstracting password input
type PasswordReader interface {
	ReadPassword(prompt string) ([]byte, error)
}

// FileWriter interface for abstracting file operations
type FileWriter interface {
	WriteFile(filename string, data []byte, perm int) error
}

// FileReader interface for abstracting file operations
type FileReader interface {
	ReadFile(filename string) ([]byte, error)
}

type Confirmer interface {
	Confirm(prompt string) bool
}
