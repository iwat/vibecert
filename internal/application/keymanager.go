package application

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/iwat/vibecert/internal/infrastructure/dblib"
)

// KeyManager handles all certificate operations
type KeyManager struct {
	db *dblib.Queries
}

// NewKeyManager creates a new key manager
func NewKeyManager(db *dblib.Queries) *KeyManager {
	return &KeyManager{
		db: db,
	}
}

// ReencryptPrivateKey changes the password of the specified private key
func (km *KeyManager) ReencryptPrivateKey(id int, currentPassword, newPassword string) error {
	key, err := km.db.KeyByID(context.TODO(), id)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
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
