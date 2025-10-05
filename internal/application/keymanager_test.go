package application

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/iwat/vibecert/internal/domain"
)

func TestKeyManager_ImportKey(t *testing.T) {
	app, _, passwordReader, fileReader, _, err := createTestApp(t)
	if err != nil {
		t.Fatalf("Failed to create test key manager: %v", err)
	}

	key, err := domain.NewRSAKey(2048, nil)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	fileReader.files["test.pem"] = []byte(key.PEMData)
	importedKeys, err := app.ImportKeys(t.Context(), "test.pem")
	if err != nil {
		t.Errorf("Failed to import key: %v", err)
	}
	if len(importedKeys) != 1 {
		t.Errorf("Expected 1 imported key, got %d", len(importedKeys))
	}

	key2, err := domain.NewRSAKey(2048, []byte("secret"))
	if err != nil {
		t.Fatalf("Failed to generate encrypted test key: %v", err)
	}
	fileReader.files["test2.pem"] = []byte(key2.PEMData)
	passwordReader.passwords = []string{"secret"}
	importedKeys, err = app.ImportKeys(t.Context(), "test2.pem")
	if err != nil {
		t.Errorf("Failed to import key: %v", err)
	}
}

func TestKeyManager_ReencryptPrivateKey(t *testing.T) {
	app, db, passwordReader, _, _, err := createTestApp(t)
	if err != nil {
		t.Fatalf("Failed to create test key manager: %v", err)
	}

	key, err := domain.NewECDSAKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	_, err = db.CreateKey(t.Context(), key)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}

	passwordReader.passwords = []string{"secret", "secret"}
	err = app.ReencryptPrivateKey(t.Context(), key.ID)
	if err != nil {
		t.Fatalf("Failed to encrypt private key: %v", err)
	}

	key, err = db.KeyByID(t.Context(), key.ID)
	if err != nil {
		t.Fatalf("Failed to get key pair: %v", err)
	}

	block, _ := pem.Decode([]byte(key.PEMData))
	if !x509.IsEncryptedPEMBlock(block) {
		t.Fatalf("Expected encrypted PEM block, got %v", block.Type)
	}

	passwordReader.passwords = []string{"secret", "newsecret", "newsecret"}
	err = app.ReencryptPrivateKey(t.Context(), key.ID)
	if err != nil {
		t.Fatalf("Failed to reencrypt private key: %v", err)
	}
}
