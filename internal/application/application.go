package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

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

// CreateCA creates a new root CA certificate
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

	template := x509.Certificate{
		Subject:               pkix.Name{CommonName: req.CommonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, req.ValidDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	if issuerPrivateKey == nil {
		privateKey, err := keyPair.Decrypt(newPassword)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
		}
		issuerPrivateKey = privateKey
	}

	var issuerCA *x509.Certificate
	if req.IssuerCA != nil {
		issuerCA = req.IssuerCA.X509Cert()
	} else {
		issuerCA = &template
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, issuerCA, issuerPrivateKey.Public(), issuerPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create x509 certificate: %v", err)
	}

	certificate, err := domain.CertificateFromPEM(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	tx := app.db.Begin()
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
