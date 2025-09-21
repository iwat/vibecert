package application

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
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

// CreateRootCA creates a new root CA certificate
type CreateRootCARequest struct {
	CommonName string
	KeySize    int
	ValidDays  int
	Password   string
}

func (app *App) CreateRootCA(req *CreateRootCARequest) (*domain.Certificate, *domain.KeyPair, error) {
	keyPair, err := domain.NewRSAKeyPair(req.KeySize, req.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, req.ValidDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	privateKey, err := keyPair.PrivateKey(req.Password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
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
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	_, err = tx.CreateKey(context.TODO(), keyPair)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create key: %v", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return certificate, keyPair, nil
}

// PasswordReader interface for abstracting password input
type PasswordReader interface {
	ReadPassword(prompt string) (string, error)
}

// FileWriter interface for abstracting file operations
type FileWriter interface {
	WriteFile(filename string, data []byte, perm int) error
}

// FileReader interface for abstracting file operations
type FileReader interface {
	ReadFile(filename string) ([]byte, error)
}
