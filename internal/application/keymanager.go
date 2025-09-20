package application

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/iwat/vibecert/internal/infrastructure/dblib"
	"golang.org/x/term"
)

// KeyManager handles all certificate operations
type KeyManager struct {
	db             *dblib.Queries
	passwordReader PasswordReader
}

// NewKeyManager creates a new key manager
func NewKeyManager(db *dblib.Queries, passwordReader PasswordReader) *KeyManager {
	return &KeyManager{
		db:             db,
		passwordReader: passwordReader,
	}
}

// ReencryptPrivateKey changes the password of the specified private key
func (km *KeyManager) ReencryptPrivateKey(id int) error {
	key, err := km.db.KeyByID(context.TODO(), id)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
	}

	var currentPassword string
	if key.IsEncrypted() {
		for {
			currentPassword, err = km.passwordReader.ReadPassword("Enter current password: ")
			if err != nil {
				return fmt.Errorf("failed to read current password: %v", err)
			}
			if key.IsEncryptedWithPassword(currentPassword) {
				break
			}
		}
	}

	newPassword, err := km.passwordReader.ReadPassword("Enter new password: ")
	if err != nil {
		return fmt.Errorf("failed to read new password: %v", err)
	}
	newPassword2, err := km.passwordReader.ReadPassword("Re-enter new password: ")
	if err != nil {
		return fmt.Errorf("failed to read new password: %v", err)
	}
	if newPassword != newPassword2 {
		return errors.New("passwords do not match")
	}

	err = key.Reencrypt(currentPassword, newPassword)
	if err != nil {
		return fmt.Errorf("failed to reencrypt private key: %v", err)
	}

	err = km.db.UpdateKeyPEM(context.TODO(), key.ID, key.PEMData)
	if err != nil {
		return fmt.Errorf("failed to update private key: %v", err)
	}

	return nil
}

func (cm *CertificateManager) encryptPrivateKey(privateKey any, password string) (string, error) {
	var keyBytes []byte
	var err error

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(key)
	default:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
	}

	if err != nil {
		return "", err
	}

	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", keyBytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(encryptedBlock)), nil
}

// PasswordReader interface for abstracting password input
type PasswordReader interface {
	ReadPassword(prompt string) (string, error)
}

// DefaultPasswordReader implements PasswordReader using terminal input
type DefaultPasswordReader struct{}

func (r *DefaultPasswordReader) ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	passwordBytes, err := term.ReadPassword(0)
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(passwordBytes), nil
}
