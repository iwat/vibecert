package application

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log"

	"github.com/iwat/vibecert/internal/domain"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
	"software.sslmate.com/src/go-pkcs12"
)

type App struct {
	db             *dblib.Queries
	passwordReader PasswordReader
	fileReader     FileReader
	fileWriter     FileWriter
}

func NewApp(db *dblib.Queries, passwordReader PasswordReader, fileReader FileReader, fileWriter FileWriter) *App {
	return &App{
		db:             db,
		passwordReader: passwordReader,
		fileReader:     fileReader,
		fileWriter:     fileWriter,
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
	KeySize                int
	ValidDays              int
	IsCA                   bool
}

const SelfSignedCertificateID = -1
const NewSubjectKeyID = -1

func (app *App) Initialize(ctx context.Context) error {
	return app.db.InitializeDatabase(ctx)
}

func (app *App) CreateCertificate(ctx context.Context, req *CreateCertificateRequest) (*domain.Certificate, *domain.Key, error) {
	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	var issuerPrivateKey domain.PrivateKey
	var issuerCertificate *domain.Certificate
	if req.IssuerCertificateID != SelfSignedCertificateID {
		var err error
		issuerCertificate, err = tx.CertificateByID(ctx, req.IssuerCertificateID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve issuer certificate: %v", err)
		}

		issuerKey, err := tx.KeyByPublicKeyHash(ctx, issuerCertificate.PublicKeyHash)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve issuer private key: %v", err)
		}
		issuerPrivateKey, err = app.tryDecryptPrivateKey(issuerKey, "issuer")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt issuer private key: %v", err)
		}
	}

	var subjectKey *domain.Key
	var subjectPublicKey crypto.PublicKey
	if req.SubjectKeyID == NewSubjectKeyID {
		newPassword, err := app.askPasswordWithConfirmation("password for the new CA")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to ask for new password: %v", err)
		}

		subjectKey, err = domain.NewRSAKey(req.KeySize, newPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
		}
		_, err = tx.CreateKey(ctx, subjectKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to store key: %v", err)
		}

		privateKey, err := subjectKey.Decrypt(newPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
		}

		if issuerPrivateKey == nil {
			issuerPrivateKey = privateKey
		}

		subjectPublicKey = privateKey.Public()
	} else {
		var err error
		subjectKey, err = app.db.KeyByID(ctx, req.SubjectKeyID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get key by ID: %v", err)
		}
		subjectPrivateKey, err := app.tryDecryptPrivateKey(subjectKey, "subject key")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt subject private key: %v", err)
		}
		subjectPublicKey = subjectPrivateKey.Public()
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

	_, err = tx.CreateCertificate(ctx, certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store certificate: %v", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return certificate, subjectKey, nil
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
	key, err := app.db.KeyByPublicKeyHash(ctx, cert.PublicKeyHash)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	privateKey, err := key.Decrypt(nil)
	if err == x509.IncorrectPasswordError {
		password, err := app.passwordReader.ReadPassword("Enter password for private key:")
		if err != nil {
			return fmt.Errorf("failed to read password: %v", err)
		}
		privateKey, err = key.Decrypt(password)
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %v", err)
		}
	}

	p12Password, err := app.askPasswordWithConfirmation("password for PKCS#12 file")
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}

	pfxData, err := pkcs12.Modern.Encode(privateKey, cert.X509Cert(), nil, string(p12Password))
	if err != nil {
		log.Fatalf("Failed to create PKCS#12 data: %v", err)
	}

	err = app.fileWriter.WriteFile(filename, pfxData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %v", err)
	}
	return nil
}

// DeleteCertificate deletes a certificate and optionally its key
type DeleteResult struct {
	Subject            string
	CertificateDeleted bool
	KeyDeleted         bool
	KeyPreserved       bool
	KeyUsageCount      int
	ChildrenCount      int
}

// DeleteCertificate deletes a certificate and optionally its key
func (app *App) DeleteCertificate(ctx context.Context, id int, force bool) (*DeleteResult, error) {
	cert, err := app.db.CertificateByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate with id %d not found", id)
		}
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	result := &DeleteResult{
		Subject: cert.SubjectDN,
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	err = app.deleteCertificateCascade(ctx, tx.Queries, cert, force, result)
	if err != nil {
		return nil, err
	}
	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}
	result.CertificateDeleted = true
	return result, err
}

func (app *App) deleteCertificateCascade(ctx context.Context, tx *dblib.Queries, cert *domain.Certificate, force bool, result *DeleteResult) error {
	childCerts, err := tx.CertificatesByIssuerAndAuthorityKeyID(ctx, cert.SubjectDN, cert.SubjectKeyID)
	if err != nil {
		return fmt.Errorf("failed to load child certificates: %v", err)
	}
	if len(childCerts) > 0 {
		if !force {
			return fmt.Errorf("cannot delete certificate with child certificates")
		}

		for _, childCert := range childCerts {
			err := app.deleteCertificateCascade(ctx, tx, childCert, force, result)
			if err != nil {
				return err
			}
		}
	} else {
		if err = tx.DeleteCertificate(ctx, cert.ID); err != nil {
			return err
		}
		result.ChildrenCount++
	}

	return nil
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
