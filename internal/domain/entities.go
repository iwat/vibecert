package domain

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Certificate represents a certificate with its metadata and relationships
type Certificate struct {
	ID                 int
	SerialNumber       string
	SubjectDN          string
	IssuerDN           string
	NotBefore          time.Time
	NotAfter           time.Time
	SignatureAlgorithm string
	SubjectKeyID       string
	AuthorityKeyID     string
	IsCA               bool
	PEMData            string
	PublicKeyHash      string
	x509Cert           *x509.Certificate
}

// CertificateFromPEM creates a Certificate instance from the given PEM block
func CertificateFromPEM(block *pem.Block) (*Certificate, error) {
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM block")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	cert := &Certificate{
		ID:                 -1,
		SerialNumber:       x509Cert.SerialNumber.String(),
		SubjectDN:          x509Cert.Subject.String(),
		IssuerDN:           x509Cert.Issuer.String(),
		NotBefore:          x509Cert.NotBefore,
		NotAfter:           x509Cert.NotAfter,
		SignatureAlgorithm: x509Cert.SignatureAlgorithm.String(),
		SubjectKeyID:       hex.EncodeToString(x509Cert.SubjectKeyId),
		AuthorityKeyID:     hex.EncodeToString(x509Cert.AuthorityKeyId),
		IsCA:               x509Cert.IsCA,
		PEMData:            string(pem.EncodeToMemory(block)),
		PublicKeyHash:      calculatePublicKeyHashFromX509Cert(x509Cert),
		x509Cert:           x509Cert,
	}

	return cert, nil
}

func (c *Certificate) X509Cert() *x509.Certificate {
	if c.x509Cert != nil {
		block, _ := pem.Decode([]byte(c.PEMData))
		x509Cert, _ := x509.ParseCertificate(block.Bytes)
		c.x509Cert = x509Cert
	}
	return c.x509Cert
}

func (c *Certificate) IsSelfSigned() bool {
	return c.SubjectDN == c.IssuerDN
}

func (c *Certificate) IsRoot() bool {
	return c.IsCA && c.IsSelfSigned()
}

// GenerateText generates a openssl "-text" representation of the certificate.
func (c *Certificate) Text() string {
	cert := c.X509Cert()
	var builder strings.Builder

	builder.WriteString("Certificate:\n")
	builder.WriteString("    Data:\n")
	builder.WriteString(fmt.Sprintf("        Version: %d\n", cert.Version))
	builder.WriteString(fmt.Sprintf("        Serial Number: %s\n", cert.SerialNumber))
	builder.WriteString("    Signature Algorithm: " + cert.SignatureAlgorithm.String() + "\n")
	builder.WriteString("        Issuer: " + cert.Issuer.String() + "\n")
	builder.WriteString("        Validity:\n")
	builder.WriteString(fmt.Sprintf("            Not Before: %s\n", cert.NotBefore.Format("Jan 2 15:04:05 2006 MST")))
	builder.WriteString(fmt.Sprintf("            Not After:  %s\n", cert.NotAfter.Format("Jan 2 15:04:05 2006 MST")))
	builder.WriteString("        Subject: " + cert.Subject.String() + "\n")

	if cert.IsCA {
		builder.WriteString("        CA: TRUE\n")
	}

	if len(cert.DNSNames) > 0 {
		builder.WriteString("        Subject Alternative Name:\n")
		for _, dns := range cert.DNSNames {
			builder.WriteString(fmt.Sprintf("            DNS:%s\n", dns))
		}
	}

	builder.WriteString("\n" + c.PEMData)

	return builder.String()
}

func calculatePublicKeyHashFromX509Cert(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

// KeyPair represents a private key with its hash
type KeyPair struct {
	ID            int
	PublicKeyHash string
	KeyType       string
	KeySize       int
	PEMData       string
	block         *pem.Block
}

type privateKeyInfo struct {
	privateKey PrivateKey
	algorithm  string
	bitSize    int
}

type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

var ErrEncryptedPrivateKey = errors.New("key is encrypted")

// NewRSAKeyPair creates a new RSA key pair with the given key size and password
func NewRSAKeyPair(keySize int, password string) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	var keyPEM string
	if password == "" {
		keyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}))
	} else {
		keyPEM, err = encryptPrivateKey(privateKey, password)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %v", err)
		}
	}
	publicKeyHash, err := calculatePublicKeyHash(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate public key hash: %v", err)
	}

	return &KeyPair{
		ID:            -1,
		PublicKeyHash: publicKeyHash,
		KeyType:       "RSA",
		KeySize:       keySize,
		PEMData:       keyPEM,
	}, nil
}

func NewECDSAKeyPair(curve elliptic.Curve, password string) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	var keyPEM string
	if password == "" {
		marshalledKey, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %v", err)
		}
		keyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: marshalledKey,
		}))
	} else {
		keyPEM, err = encryptPrivateKey(privateKey, password)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %v", err)
		}
	}
	publicKeyHash, err := calculatePublicKeyHash(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate public key hash: %v", err)
	}

	return &KeyPair{
		ID:            -1,
		PublicKeyHash: publicKeyHash,
		KeyType:       "ECDSA/" + curve.Params().Name,
		KeySize:       curve.Params().BitSize,
		PEMData:       keyPEM,
	}, nil
}

// KeyPairFromUnencryptedPEM creates a KeyPair instance from the given unencrypted PEM block
func KeyPairFromUnencryptedPEM(block *pem.Block) (*KeyPair, error) {
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, ErrEncryptedPrivateKey
	}
	keyPair, err := keyPairFromPrivateKeyBytes(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		ID:            keyPair.ID,
		PublicKeyHash: keyPair.PublicKeyHash,
		KeyType:       keyPair.KeyType,
		KeySize:       keyPair.KeySize,
		PEMData:       string(pem.EncodeToMemory(block)),
	}, nil
}

// KeyPairFromPEM creates a KeyPair instance from the given encrypted PEM block with the specified password
func KeyPairFromPEM(block *pem.Block, password string) (*KeyPair, error) {
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("encrypted PKCS#8 is not supported")
	}

	keyBytes, err := decryptPEM(block, password)
	if err != nil {
		return nil, err
	}

	keyPair, err := keyPairFromPrivateKeyBytes(keyBytes)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		ID:            keyPair.ID,
		PublicKeyHash: keyPair.PublicKeyHash,
		KeyType:       keyPair.KeyType,
		KeySize:       keyPair.KeySize,
		PEMData:       string(pem.EncodeToMemory(block)),
	}, nil
}

func (k *KeyPair) PrivateKey(password string) (PrivateKey, error) {
	block, _ := pem.Decode([]byte(k.PEMData))

	keyBytes, err := decryptPEM(block, password)
	if err != nil {
		return nil, err
	}

	privateKeyInfo, err := loadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	return privateKeyInfo.privateKey, nil
}

// Reencrypt changes the password of a private key
func (k *KeyPair) Reencrypt(currentPassword, newPassword string) error {
	privateKey, err := k.PrivateKey(currentPassword)
	if err != nil {
		return err
	}

	newKeyData, err := encryptPrivateKey(privateKey, newPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key with new password: %v", err)
	}

	k.PEMData = newKeyData
	return nil
}

func (k *KeyPair) IsEncrypted() bool {
	return x509.IsEncryptedPEMBlock(k.Block())
}

func (k *KeyPair) IsEncryptedWithPassword(password string) bool {
	if !k.IsEncrypted() {
		return false
	}

	_, err := x509.DecryptPEMBlock(k.Block(), []byte(password))
	return err == nil
}

func (k *KeyPair) Block() *pem.Block {
	if k.block == nil {
		block, _ := pem.Decode([]byte(k.PEMData))
		k.block = block
	}
	return k.block
}

func encryptPrivateKey(privateKey PrivateKey, password string) (string, error) {
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

func decryptPEM(block *pem.Block, password string) ([]byte, error) {
	var keyBytes []byte
	var err error
	if x509.IsEncryptedPEMBlock(block) {
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		keyBytes = block.Bytes
	}
	return keyBytes, nil
}

// keyPairFromPrivateKeyBytes creates an incomplete KeyPair instance from the given private key bytes.
// The constructed KeyPair instance will have a empty PEMData field.
func keyPairFromPrivateKeyBytes(keyBytes []byte) (*KeyPair, error) {
	privateKey, err := loadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	keyHash, err := calculatePublicKeyHash(privateKey.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate key hash: %v", err)
	}

	return &KeyPair{-1, keyHash, privateKey.algorithm, privateKey.bitSize, "", nil}, nil
}

func loadPrivateKeyFromPEM(keyBytes []byte) (privateKeyInfo, error) {
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return privateKeyInfo{key, "RSA", key.Size() * 8}, nil
	}
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return privateKeyInfo{key, "ECDSA/" + key.Params().Name, key.Params().BitSize}, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		switch priv := key.(type) {
		case *rsa.PrivateKey:
			return privateKeyInfo{priv, "RSA", priv.Size() * 8}, nil
		case *ecdsa.PrivateKey:
			return privateKeyInfo{priv, "ECDSA/" + priv.Params().Name, priv.Params().BitSize}, nil
		case ed25519.PrivateKey:
			return privateKeyInfo{priv, "Ed25519", len(priv) * 8}, nil
		case *ecdh.PrivateKey:
			return privateKeyInfo{priv, "ECDH", len(priv.Bytes()) * 8}, nil
		default:
			return privateKeyInfo{}, fmt.Errorf("unsupported private key type: %T", key)
		}
	}

	return privateKeyInfo{}, fmt.Errorf("failed to parse private key")
}

func calculatePublicKeyHash(privateKey PrivateKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	hash := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(hash[:]), nil
}
