package domain

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

// Certificate represents a certificate with its metadata and relationships
type Certificate struct {
	SerialNumber string
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	PEMData      string
	KeyHash      string
	IsSelfSigned bool
	IsRoot       bool
	IsCA         bool
	X509Cert     *x509.Certificate
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
		SerialNumber: x509Cert.SerialNumber.String(),
		Subject:      x509Cert.Subject.String(),
		Issuer:       x509Cert.Issuer.String(),
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		PEMData:      string(pem.EncodeToMemory(block)),
		KeyHash:      calculatePublicKeyHashFromX509Cert(x509Cert),
		IsSelfSigned: x509Cert.Subject.String() == x509Cert.Issuer.String(),
		IsRoot:       x509Cert.IsCA && x509Cert.Subject.String() == x509Cert.Issuer.String(),
		IsCA:         x509Cert.IsCA,
		X509Cert:     x509Cert,
	}

	return cert, nil
}

func calculatePublicKeyHashFromX509Cert(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

// KeyPair represents a private key with its hash
type KeyPair struct {
	PublicKeyHash    string
	KeyAlgorithm     string
	PrivateKeyLength int
	PEMData          string
}

type privateKeyInfo struct {
	privateKey privateKey
	algorithm  string
	bitSize    int
}

type privateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// KeyPairFromUnencryptedPEM creates a KeyPair instance from the given unencrypted PEM block
func KeyPairFromUnencryptedPEM(block *pem.Block) (*KeyPair, error) {
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	keyPair, err := keyPairFromPrivateKeyBytes(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PublicKeyHash:    keyPair.PublicKeyHash,
		KeyAlgorithm:     keyPair.KeyAlgorithm,
		PrivateKeyLength: keyPair.PrivateKeyLength,
		PEMData:          string(pem.EncodeToMemory(block)),
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

	var keyBytes []byte
	var err error
	if x509.IsEncryptedPEMBlock(block) {
		fmt.Println("Decrypting PEM block")
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		keyBytes = block.Bytes
	}

	keyPair, err := keyPairFromPrivateKeyBytes(keyBytes)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PublicKeyHash:    keyPair.PublicKeyHash,
		KeyAlgorithm:     keyPair.KeyAlgorithm,
		PrivateKeyLength: keyPair.PrivateKeyLength,
		PEMData:          string(pem.EncodeToMemory(block)),
	}, nil
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

	return &KeyPair{keyHash, privateKey.algorithm, privateKey.bitSize, ""}, nil
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

func calculatePublicKeyHash(privateKey privateKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	hash := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(hash[:]), nil
}
