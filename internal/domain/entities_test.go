package domain

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// NOTE: OpenSSL-encrypted PKCS8 is not supported by Go built-in crypto libraries.
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
		t.Errorf("failed to read %s: %v", name, err)
	}
	block, _ := pem.Decode(data)
	return block
}

func TestNewCertificate_SelfSigned(t *testing.T) {
	issuerPrivateKey := generateRandomPrivateKey(t)

	req := &CreateCertificateRequest{
		IssuerCertificate: nil,
		IssuerPrivateKey:  issuerPrivateKey,
		CommonName:        "example.com",
		ValidDays:         1,
		IsCA:              true,
		PublicKey:         issuerPrivateKey.Public(),
	}

	cert, err := NewCertificate(req)
	if err != nil {
		t.Errorf("NewCertificate failed: %v", err)
	}
	if cert == nil {
		t.Errorf("NewCertificate returned nil")
	}

	if cert.IssuerDN != cert.SubjectDN {
		t.Errorf("cert.IssuerDN (%s) should be equal to cert.SubjectDN (%s)", cert.IssuerDN, cert.SubjectDN)
	}
	if cert.X509Cert().Issuer.String() != cert.X509Cert().Subject.String() {
		t.Errorf("x509.Issuer (%s) should be equal to x509.Subject (%s)", cert.X509Cert().Issuer.String(), cert.X509Cert().Subject.String())
	}
	if cert.IssuerDN != cert.X509Cert().Issuer.String() {
		t.Errorf("cert.IssuerDN (%s) should be equal to x509.Issuer (%s)", cert.IssuerDN, cert.X509Cert().Issuer.String())
	}
}

func TestNewCertificate_NonSelfSigned(t *testing.T) {
	issuerPrivateKey := generateRandomPrivateKey(t)
	issuerCert := createCertificate(t, issuerPrivateKey, issuerPrivateKey.Public())

	subjectPrivateKey := generateRandomPrivateKey(t)

	req := &CreateCertificateRequest{
		IssuerCertificate: &Certificate{
			IsCA:     true,
			x509Cert: issuerCert,
		},
		IssuerPrivateKey: issuerPrivateKey,
		CommonName:       "example.com",
		ValidDays:        1,
		IsCA:             true,
		PublicKey:        subjectPrivateKey.Public(),
	}

	cert, err := NewCertificate(req)
	if err != nil {
		t.Fatalf("NewCertificate failed: %v", err)
	}
	if cert == nil {
		t.Errorf("NewCertificate returned nil")
	}

	if cert.IssuerDN == cert.SubjectDN {
		t.Errorf("cert.IssuerDN (%s) should not be equal to cert.SubjectDN (%s)", cert.IssuerDN, cert.SubjectDN)
	}
	if cert.X509Cert().Issuer.String() == cert.X509Cert().Subject.String() {
		t.Errorf("x509.Issuer (%s) should not be equal to x509.Subject (%s)", cert.X509Cert().Issuer.String(), cert.X509Cert().Subject.String())
	}
}

func generateRandomPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	return privateKey
}

func createCertificate(t *testing.T, issuerPrivateKey *rsa.PrivateKey, subjectPublicKey crypto.PublicKey) *x509.Certificate {
	t.Helper()

	issuerCertTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Issuer"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, issuerCertTemplate, issuerCertTemplate, subjectPublicKey, issuerPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	rawCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return rawCert
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
		t.Errorf("key.PublicKeyHash != cert.PublicKeyHash")
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
