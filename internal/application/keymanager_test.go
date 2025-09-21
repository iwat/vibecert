package application

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/iwat/vibecert/internal/domain"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
)

func TestKeyManager_ReencryptPrivateKey(t *testing.T) {
	km, db, passwordReader, _, err := createTestKeyManager()
	if err != nil {
		t.Fatalf("Failed to create test key manager: %v", err)
	}

	keyPair, err := domain.NewECDSAKeyPair(elliptic.P256(), "")
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	_, err = db.CreateKey(t.Context(), keyPair)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}

	passwordReader.passwords = []string{"secret", "secret"}
	err = km.ReencryptPrivateKey(keyPair.ID)
	if err != nil {
		t.Fatalf("Failed to encrypt private key: %v", err)
	}

	keyPair, err = db.KeyByID(t.Context(), keyPair.ID)
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	block, _ := pem.Decode([]byte(keyPair.PEMData))
	if !x509.IsEncryptedPEMBlock(block) {
		t.Fatalf("Expected encrypted PEM block, got %v", block.Type)
	}

	passwordReader.passwords = []string{"secret", "newsecret", "newsecret"}
	err = km.ReencryptPrivateKey(keyPair.ID)
	if err != nil {
		t.Fatalf("Failed to reencrypt private key: %v", err)
	}
}

func TestKeyManager_ImportKey(t *testing.T) {
	km, _, passwordReader, fileReader, err := createTestKeyManager()
	if err != nil {
		t.Fatalf("Failed to create test key manager: %v", err)
	}

	keyPair, err := domain.NewRSAKeyPair(2048, "")
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	fileReader.files["test.pem"] = []byte(keyPair.PEMData)
	err = km.ImportKey("test.pem")
	if err != nil {
		t.Errorf("Failed to import key: %v", err)
	}

	keyPair2, err := domain.NewRSAKeyPair(2048, "secret")
	if err != nil {
		t.Fatalf("Failed to generate encrypted test key: %v", err)
	}
	fileReader.files["test2.pem"] = []byte(keyPair2.PEMData)
	passwordReader.passwords = []string{"secret"}
	err = km.ImportKey("test2.pem")
	if err != nil {
		t.Errorf("Failed to import key: %v", err)
	}
}

// Test helper to create test key manager with real database
func createTestKeyManager() (*KeyManager, *dblib.Queries, *MockPasswordReader, *MockFileReader, error) {
	db, err := createTestDatabase()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	passwordReader := NewMockPasswordReader()
	fileReader := NewMockFileReader()

	return NewKeyManager(db, passwordReader, fileReader), db, passwordReader, fileReader, nil
}
