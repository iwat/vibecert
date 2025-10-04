package application

import (
	"bytes"
	"context"
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

// CreateCARequest provides a request to create a new root CA certificate
type CreateCARequest struct {
	IssuerCA               *domain.Certificate
	CommonName             string
	CountryName            string
	StateName              string
	LocalityName           string
	OrganizationName       string
	OrganizationalUnitName string
	KeySize                int
	ValidDays              int
}

func (app *App) Initialize(ctx context.Context) error {
	return app.db.InitializeDatabase(ctx)
}

func (app *App) CreateCA(ctx context.Context, req *CreateCARequest) (*domain.Certificate, *domain.KeyPair, error) {
	var issuerPrivateKey domain.PrivateKey
	if req.IssuerCA != nil {
		issuerKeyPair, err := app.db.KeyByPublicKeyHash(ctx, req.IssuerCA.PublicKeyHash)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve issuer private key: %v", err)
		}
		password, err := app.passwordReader.ReadPassword("Enter password of the issuer: ")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read password: %v", err)
		}
		issuerPrivateKey, err = issuerKeyPair.Decrypt(password)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt issuer private key: %v", err)
		}
	}

	newPassword, err := app.askPasswordWithConfirmation("new password")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ask for new password: %v", err)
	}

	keyPair, err := domain.NewRSAKeyPair(req.KeySize, newPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	privateKey, err := keyPair.Decrypt(newPassword)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	if issuerPrivateKey == nil {
		issuerPrivateKey = privateKey
	}

	certificate, err := domain.NewCertificate(&domain.CreateCertificateRequest{
		IssuerCertificate:      req.IssuerCA,
		IssuerPrivateKey:       issuerPrivateKey,
		CommonName:             req.CommonName,
		CountryName:            req.CountryName,
		StateName:              req.StateName,
		LocalityName:           req.LocalityName,
		OrganizationName:       req.OrganizationName,
		OrganizationalUnitName: req.OrganizationalUnitName,
		ValidDays:              req.ValidDays,
		IsCA:                   true,
		PublicKey:              privateKey.Public(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	_, err = tx.CreateCertificate(ctx, certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store certificate: %v", err)
	}
	_, err = tx.CreateKey(ctx, keyPair)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store key: %v", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return certificate, keyPair, nil
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
