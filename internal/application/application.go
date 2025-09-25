package application

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/iwat/vibecert/internal/domain"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
)

type App struct {
	db             *dblib.Queries
	passwordReader PasswordReader
	fileReader     FileReader
}

func NewApp(db *dblib.Queries, passwordReader PasswordReader, fileReader FileReader) *App {
	return &App{
		db:             db,
		passwordReader: passwordReader,
		fileReader:     fileReader,
	}
}

// CreateCARequest provides a request to create a new root CA certificate
type CreateCARequest struct {
	IssuerCA   *domain.Certificate
	CommonName string
	KeySize    int
	ValidDays  int
}

func (app *App) CreateCA(req *CreateCARequest) (*domain.Certificate, *domain.KeyPair, error) {
	var issuerPrivateKey domain.PrivateKey
	if req.IssuerCA != nil {
		issuerKeyPair, err := app.db.KeyByPublicKeyHash(context.TODO(), req.IssuerCA.PublicKeyHash)
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

	newPassword, err := app.askNewPassword()
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
		IssuerCertificate: req.IssuerCA,
		IssuerPrivateKey:  issuerPrivateKey,
		CommonName:        req.CommonName,
		ValidDays:         req.ValidDays,
		IsCA:              true,
		PublicKey:         privateKey.Public(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	tx := app.db.Begin(context.TODO())
	defer tx.Rollback()

	_, err = tx.CreateCertificate(context.TODO(), certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store certificate: %v", err)
	}
	_, err = tx.CreateKey(context.TODO(), keyPair)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store key: %v", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return certificate, keyPair, nil
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

func (app *App) DeleteCertificate(id int, force bool) (*DeleteResult, error) {
	cert, err := app.db.CertificateByID(context.TODO(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate with id %d not found", id)
		}
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	result := &DeleteResult{
		Subject: cert.SubjectDN,
	}

	tx := app.db.Begin(context.TODO())
	defer tx.Rollback()

	err = app.deleteCertificateCascade(tx.Queries, cert, force, result)
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

func (app *App) deleteCertificateCascade(tx *dblib.Queries, cert *domain.Certificate, force bool, result *DeleteResult) error {
	childCerts, err := tx.CertificatesByIssuerAndAuthorityKeyID(context.TODO(), cert.SubjectDN, cert.SubjectKeyID)
	if err != nil {
		return fmt.Errorf("failed to load child certificates: %v", err)
	}
	if len(childCerts) > 0 {
		if !force {
			return fmt.Errorf("cannot delete certificate with child certificates")
		}

		for _, childCert := range childCerts {
			err := app.deleteCertificateCascade(tx, childCert, force, result)
			if err != nil {
				return err
			}
		}
	} else {
		if err = tx.DeleteCertificate(context.TODO(), cert.ID); err != nil {
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

func (app *App) askNewPassword() ([]byte, error) {
	password, err := app.passwordReader.ReadPassword("Enter new password: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}
	password2, err := app.passwordReader.ReadPassword("Enter new password again: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}
	if !bytes.Equal(password, password2) {
		return nil, fmt.Errorf("passwords do not match")
	}
	return []byte(password), nil
}
