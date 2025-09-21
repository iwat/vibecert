package application

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/iwat/vibecert/internal/domain"
)

func TestKeyManager_ImportKey(t *testing.T) {
	app, _, passwordReader, fileReader, err := createTestApp()
	if err != nil {
		t.Fatalf("Failed to create test key manager: %v", err)
	}

	keyPair, err := domain.NewRSAKeyPair(2048, nil)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	fileReader.files["test.pem"] = []byte(keyPair.PEMData)
	err = app.ImportKey("test.pem")
	if err != nil {
		t.Errorf("Failed to import key: %v", err)
	}

	keyPair2, err := domain.NewRSAKeyPair(2048, []byte("secret"))
	if err != nil {
		t.Fatalf("Failed to generate encrypted test key: %v", err)
	}
	fileReader.files["test2.pem"] = []byte(keyPair2.PEMData)
	passwordReader.passwords = []string{"secret"}
	err = app.ImportKey("test2.pem")
	if err != nil {
		t.Errorf("Failed to import key: %v", err)
	}
}

func TestKeyManager_ReencryptPrivateKey(t *testing.T) {
	app, db, passwordReader, _, err := createTestApp()
	if err != nil {
		t.Fatalf("Failed to create test key manager: %v", err)
	}

	keyPair, err := domain.NewECDSAKeyPair(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	_, err = db.CreateKey(t.Context(), keyPair)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}

	passwordReader.passwords = []string{"secret", "secret"}
	err = app.ReencryptPrivateKey(keyPair.ID)
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
	err = app.ReencryptPrivateKey(keyPair.ID)
	if err != nil {
		t.Fatalf("Failed to reencrypt private key: %v", err)
	}
}
