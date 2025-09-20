package domain

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

//go:generate bash ./generate_testdata.sh

var unencryptedKeyFiles = []string{
	"ecdh_key_pkcs8.pem",
	"ecdsa_key_pkcs8.pem",
	"ecdsa_key_sec1.pem",
	"ed25519_key_pkcs8.pem",
	"rsa_key_pkcs1.pem",
	"rsa_key_pkcs8.pem",
}

var encryptedKeyFiles = []string{
	//"ecdh_key_pkcs8_enc.pem",
	//"ecdsa_key_pkcs8_enc.pem",
	"ecdsa_key_sec1_enc.pem",
	//"ed25519_key_pkcs8_enc.pem",
	"rsa_key_pkcs1_enc.pem",
	//"rsa_key_pkcs8_enc.pem",
}

func loadTestFile(t *testing.T, name string) *pem.Block {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("failed to read %s: %v", name, err)
	}
	block, _ := pem.Decode(data)
	return block
}

func TestCertificateFromPEM(t *testing.T) {
	certPEM := loadTestFile(t, "rsa_cert.crt")
	cert, err := CertificateFromPEM(certPEM)
	if err != nil {
		t.Errorf("CertificateFromPEM failed: %v", err)
	}

	keyPEM := loadTestFile(t, "rsa_cert_key.pem")
	key, _ := KeyPairFromUnencryptedPEM(keyPEM)

	if key.PublicKeyHash != cert.PublicKeyHash {
		t.Fatalf("key.PublicKeyHash != cert.PublicKeyHash")
	}
}

func TestUnencryptedKeyPairFromUnencryptedPEM(t *testing.T) {
	for _, keyFile := range unencryptedKeyFiles {
		t.Run(keyFile, func(t *testing.T) {
			keyPEM := loadTestFile(t, keyFile)
			if _, err := KeyPairFromUnencryptedPEM(keyPEM); err != nil {
				t.Errorf("Unencrypted via KeyPairFromUnencryptedPEM failed: %v", err)
			}
		})
	}
}

func TestUnencryptedKeyPairFromPEM(t *testing.T) {
	for _, keyFile := range unencryptedKeyFiles {
		t.Run(keyFile, func(t *testing.T) {
			keyPEM := loadTestFile(t, keyFile)
			if _, err := KeyPairFromPEM(keyPEM, ""); err != nil {
				t.Errorf("Unencrypted via KeyPairFromPEM failed: %v", err)
			}
		})
	}
}

func TestEncryptedKeyPairFromPEM(t *testing.T) {
	for _, keyFile := range encryptedKeyFiles {
		t.Run(keyFile, func(t *testing.T) {
			keyPEM := loadTestFile(t, keyFile)
			if _, err := KeyPairFromPEM(keyPEM, "secret"); err != nil {
				t.Errorf("Unencrypted via KeyPairFromPEM failed: %v", err)
			}
		})
	}
}

func TestReencryptedKeyPairFromPEM(t *testing.T) {
	for _, keyFile := range encryptedKeyFiles {
		t.Run(keyFile, func(t *testing.T) {
			keyPEM := loadTestFile(t, keyFile)
			var keyPair *KeyPair
			var err error
			if keyPair, err = KeyPairFromPEM(keyPEM, "secret"); err != nil {
				t.Errorf("Unencrypted via KeyPairFromPEM failed: %v", err)
			}
			err = keyPair.Reencrypt("secret", "newsecret")
			if err != nil {
				t.Errorf("Reencryption failed: %v", err)
			}

			block, _ := pem.Decode([]byte(keyPair.PEMData))
			if keyPair, err = KeyPairFromPEM(block, "newsecret"); err != nil {
				t.Errorf("Unencrypted via KeyPairFromPEM failed: %v", err)
			}
		})
	}
}
