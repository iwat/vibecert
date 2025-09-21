package domain

import (
	"crypto/elliptic"
	"crypto/x509"
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
			if _, err := KeyPairFromPEM(keyPEM, nil); err != nil {
				t.Errorf("Unencrypted via KeyPairFromPEM failed: %v", err)
			}
		})
	}
}

func TestEncryptedKeyPairFromPEM(t *testing.T) {
	for _, keyFile := range encryptedKeyFiles {
		t.Run(keyFile, func(t *testing.T) {
			keyPEM := loadTestFile(t, keyFile)
			if _, err := KeyPairFromPEM(keyPEM, []byte("secret")); err != nil {
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
			if keyPair, err = KeyPairFromPEM(keyPEM, []byte("secret")); err != nil {
				t.Errorf("Unencrypted via KeyPairFromPEM failed: %v", err)
			}
			err = keyPair.Reencrypt([]byte("secret"), []byte("newsecret"))
			if err != nil {
				t.Errorf("Reencryption failed: %v", err)
			}

			block, _ := pem.Decode([]byte(keyPair.PEMData))
			if keyPair, err = KeyPairFromPEM(block, []byte("newsecret")); err != nil {
				t.Errorf("Unencrypted via KeyPairFromPEM failed: %v", err)
			}
		})
	}
}

func TestNewRSAKeyPair(t *testing.T) {
	key, err := NewRSAKeyPair(2048, nil)
	if err != nil {
		t.Errorf("NewRSAKeyPair failed: %v", err)
	}
	if key == nil {
		t.Errorf("NewRSAKeyPair returned nil")
	}

	key, err = NewRSAKeyPair(2048, []byte("secret"))
	if err != nil {
		t.Errorf("NewRSAKeyPair (encrypted) failed: %v", err)
	}
	if key == nil {
		t.Errorf("NewRSAKeyPair (encrypted) returned nil")
	}

	_, err = key.Decrypt([]byte("badpassword"))
	if err != x509.IncorrectPasswordError {
		t.Errorf("KeyPair should be encrypted")
	}

	_, err = key.Decrypt([]byte("secret"))
	if err != nil {
		t.Errorf("KeyPair is not encrypted with desired password")
	}
}

func TestNewECDSAKeyPair(t *testing.T) {
	key, err := NewECDSAKeyPair(elliptic.P256(), nil)
	if err != nil {
		t.Errorf("NewECDSAKeyPair failed: %v", err)
	}
	if key == nil {
		t.Errorf("NewECDSAKeyPair returned nil")
	}

	key, err = NewECDSAKeyPair(elliptic.P256(), []byte("secret"))
	if err != nil {
		t.Errorf("NewECDSAKeyPair (encrypted) failed: %v", err)
	}
	if key == nil {
		t.Errorf("NewECDSAKeyPair (encrypted) returned nil")
	}

	_, err = key.Decrypt([]byte("badpassword"))
	if err != x509.IncorrectPasswordError {
		t.Errorf("KeyPair should be encrypted")
	}

	_, err = key.Decrypt([]byte("secret"))
	if err != nil {
		t.Errorf("KeyPair is not encrypted with desired password")
	}
}
