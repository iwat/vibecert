package application

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/iwat/vibecert/internal/domain"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
)

func TestKeyManager_ReencryptPrivateKey(t *testing.T) {
	km, db, err := createTestKeyManager()
	if err != nil {
		t.Fatalf("Failed to create test key manager: %v", err)
	}

	keyPEM, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	keyPair, err := db.CreateKey(t.Context(), &domain.KeyPair{
		ID:            -1,
		PublicKeyHash: "hash",
		KeyType:       "rsa",
		KeySize:       2048,
		PEMData:       keyPEM,
	})
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}

	err = km.ReencryptPrivateKey(keyPair.ID, "", "secret")
	if err != nil {
		t.Errorf("Failed to reencrypt private key: %v", err)
	}

	keyPair, err = db.KeyByID(t.Context(), keyPair.ID)
	if err != nil {
		t.Errorf("Failed to get key pair: %v", err)
	}

	block, _ := pem.Decode([]byte(keyPair.PEMData))
	if !x509.IsEncryptedPEMBlock(block) {
		t.Errorf("Expected encrypted PEM block, got %v", block.Type)
	}

	err = km.ReencryptPrivateKey(keyPair.ID, "secret", "newsecret")
	if err != nil {
		t.Errorf("Failed to reencrypt private key: %v", err)
	}
}

// Test helper to create test key manager with real database
func createTestKeyManager() (*KeyManager, *dblib.Queries, error) {
	db, err := createTestDatabase()
	if err != nil {
		return nil, nil, err
	}

	return NewKeyManager(db), db, nil
}

// Generate a valid test key pair
func generateTestKey() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})), nil
}
