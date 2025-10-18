package domain

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"strconv"
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

// CreateCertificateRequest provides a request to create a new certificate
type CreateCertificateRequest struct {
	IssuerCertificate      *Certificate
	IssuerPrivateKey       crypto.PrivateKey
	CommonName             string
	CountryName            string
	StateName              string
	LocalityName           string
	OrganizationName       string
	OrganizationalUnitName string
	ValidDays              int
	IsCA                   bool
	PublicKey              crypto.PublicKey
}

func NewCertificate(req *CreateCertificateRequest) (*Certificate, error) {
	subject := pkix.Name{CommonName: req.CommonName}
	if req.CountryName != "" {
		subject.Country = []string{req.CountryName}
	}
	if req.StateName != "" {
		subject.Province = []string{req.StateName}
	}
	if req.LocalityName != "" {
		subject.Locality = []string{req.LocalityName}
	}
	if req.OrganizationName != "" {
		subject.Organization = []string{req.OrganizationName}
	}
	if req.OrganizationalUnitName != "" {
		subject.OrganizationalUnit = []string{req.OrganizationalUnitName}
	}
	template := x509.Certificate{
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, req.ValidDays),
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
	}
	if req.IsCA {
		template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	} else {
		template.KeyUsage = x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageCodeSigning,
		}
	}

	var issuer *x509.Certificate
	if req.IssuerCertificate != nil {
		if !req.IssuerCertificate.IsCA {
			return nil, fmt.Errorf("issuer is not a CA")
		}
		issuer = req.IssuerCertificate.X509Cert()
	} else {
		issuer = &template
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, issuer, req.PublicKey, req.IssuerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 certificate: %v", err)
	}

	certificate, err := CertificateFromPEM(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return certificate, nil
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
		SerialNumber:       bigIntToHex(x509Cert.SerialNumber),
		SubjectDN:          x509Cert.Subject.String(),
		IssuerDN:           x509Cert.Issuer.String(),
		NotBefore:          x509Cert.NotBefore,
		NotAfter:           x509Cert.NotAfter,
		SignatureAlgorithm: x509Cert.SignatureAlgorithm.String(),
		SubjectKeyID:       bytesToHex(x509Cert.SubjectKeyId),
		AuthorityKeyID:     bytesToHex(x509Cert.AuthorityKeyId),
		IsCA:               x509Cert.IsCA,
		PEMData:            string(pem.EncodeToMemory(block)),
		PublicKeyHash:      calculatePublicKeyHashFromX509Cert(x509Cert),
		x509Cert:           x509Cert,
	}

	return cert, nil
}

func (c *Certificate) X509Cert() *x509.Certificate {
	if c.x509Cert == nil {
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
	path, err := exec.LookPath("openssl")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		var stdout bytes.Buffer
		cmd := exec.Command(path, "x509", "-text")
		cmd.Stdin = strings.NewReader(c.PEMData)
		cmd.Stdout = &stdout
		err = cmd.Run()
		if err != nil {
			fmt.Println(err)
		} else {
			return strings.TrimSpace(string(stdout.Bytes()))
		}
	}

	return strings.TrimSpace(c.PEMData)
}

func (c *Certificate) String() string {
	return fmt.Sprintf("(📜 %d) %s 🔢 %s...", c.ID, c.SubjectDN, c.SerialNumber[:12])
}

func calculatePublicKeyHashFromX509Cert(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// Key represents an asymmetric private key
type Key struct {
	ID            int
	PublicKeyHash string
	KeySpec       string
	PEMData       string
	block         *pem.Block
}

type privateKeyInfo struct {
	privateKey PrivateKey
	spec       string
}

type PrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

var ErrEncryptedPrivateKey = errors.New("key is encrypted")

// NewRSAKey creates a new RSA key pair with the given key size and password
func NewRSAKey(keySize int, password []byte) (*Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	var keyPEM string
	if len(password) == 0 {
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

	return &Key{
		ID:            -1,
		PublicKeyHash: publicKeyHash,
		KeySpec:       "RSA" + strconv.Itoa(keySize),
		PEMData:       keyPEM,
	}, nil
}

func NewECDSAKey(curve elliptic.Curve, password []byte) (*Key, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	var keyPEM string
	if len(password) == 0 {
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

	return &Key{
		ID:            -1,
		PublicKeyHash: publicKeyHash,
		KeySpec:       "ECDSA" + strconv.Itoa(curve.Params().BitSize),
		PEMData:       keyPEM,
	}, nil
}

// KeyFromUnencryptedPEM creates a Key instance from the given unencrypted PEM block
func KeyFromUnencryptedPEM(block *pem.Block) (*Key, error) {
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, ErrEncryptedPrivateKey
	}
	key, err := keyFromPrivateKeyBytes(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Key{
		ID:            key.ID,
		PublicKeyHash: key.PublicKeyHash,
		KeySpec:       key.KeySpec,
		PEMData:       string(pem.EncodeToMemory(block)),
	}, nil
}

// KeyFromPEM creates a Key instance from the given encrypted PEM block with the specified password
func KeyFromPEM(block *pem.Block, password []byte) (*Key, error) {
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("encrypted PKCS#8 is not supported")
	}

	keyBytes, _, err := decryptPEM(block, password)
	if err != nil {
		return nil, err
	}

	key, err := keyFromPrivateKeyBytes(keyBytes)
	if err != nil {
		return nil, err
	}
	return &Key{
		ID:            key.ID,
		PublicKeyHash: key.PublicKeyHash,
		KeySpec:       key.KeySpec,
		PEMData:       string(pem.EncodeToMemory(block)),
	}, nil
}

func (k *Key) Decrypt(password []byte) (PrivateKey, error) {
	block, _ := pem.Decode([]byte(k.PEMData))

	keyBytes, decrypted, err := decryptPEM(block, password)
	if err != nil {
		return nil, err
	}

	privateKeyInfo, err := loadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	if decrypted {
		slog.Info("decrypted", "key", k)
	}
	return privateKeyInfo.privateKey, nil
}

// Reencrypt changes the password of a private key
func (k *Key) Reencrypt(currentPassword, newPassword []byte) error {
	privateKey, err := k.Decrypt(currentPassword)
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

func (k *Key) IsEncrypted() bool {
	return x509.IsEncryptedPEMBlock(k.Block())
}

func (k *Key) Block() *pem.Block {
	if k.block == nil {
		block, _ := pem.Decode([]byte(k.PEMData))
		k.block = block
	}
	return k.block
}

func (k *Key) String() string {
	return fmt.Sprintf("(🔑 %d) %s (%s)", k.ID, k.PublicKeyHash, k.KeySpec)
}

func encryptPrivateKey(privateKey PrivateKey, password []byte) (string, error) {
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

func decryptPEM(block *pem.Block, password []byte) ([]byte, bool, error) {
	var keyBytes []byte
	var err error
	var decrypted bool
	if x509.IsEncryptedPEMBlock(block) {
		if len(password) == 0 {
			return nil, false, ErrEncryptedPrivateKey
		}

		keyBytes, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, false, err
		}
		decrypted = true
	} else {
		keyBytes = block.Bytes
	}
	return keyBytes, decrypted, nil
}

// keyFromPrivateKeyBytes creates an incomplete Key instance from the given private key bytes.
// The constructed Key instance will have a empty PEMData field.
func keyFromPrivateKeyBytes(keyBytes []byte) (*Key, error) {
	privateKey, err := loadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	keyHash, err := calculatePublicKeyHash(privateKey.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate key hash: %v", err)
	}

	return &Key{-1, keyHash, privateKey.spec, "", nil}, nil
}

func loadPrivateKeyFromPEM(keyBytes []byte) (privateKeyInfo, error) {
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return privateKeyInfo{key, "RSA" + strconv.Itoa(key.Size()*8)}, nil
	}
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return privateKeyInfo{key, "ECDSA" + strconv.Itoa(key.Params().BitSize)}, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		switch priv := key.(type) {
		case *rsa.PrivateKey:
			return privateKeyInfo{priv, "RSA" + strconv.Itoa(priv.Size()*8)}, nil
		case *ecdsa.PrivateKey:
			return privateKeyInfo{priv, "ECDSA" + strconv.Itoa(priv.Params().BitSize)}, nil
		case ed25519.PrivateKey:
			return privateKeyInfo{priv, "Ed25519/" + strconv.Itoa(len(priv)*8)}, nil
		case *ecdh.PrivateKey:
			return privateKeyInfo{priv, "ECDH" + strconv.Itoa(len(priv.Bytes())*8)}, nil
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
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func bigIntToHex(i *big.Int) string {
	var parts []string
	for _, b := range i.Bytes() {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, ":")
}

func bytesToHex(b []byte) string {
	var parts []string
	for _, b := range b {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, ":")
}

func marshalPublicKey(pub any) string {
	var output strings.Builder
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		output.WriteString(fmt.Sprintf("Public-Key: (%d bit)\n", pub.Size()))
		output.WriteString("Modulus:\n")
		output.WriteString(pub.N.Text(16))
		output.WriteString(fmt.Sprintf("Exponent: %d", pub.E))
	case *ecdsa.PublicKey:
		output.WriteString(fmt.Sprintf("Public-Key: (%d bit)\n", pub.Params().BitSize))
		output.WriteString("pub:\n")
		output.WriteString(wrap(bigIntToHex(pub.X)+":"+bigIntToHex(pub.Y), 42, 4))
		output.WriteString("\n")
		output.WriteString(fmt.Sprintf("NIST CURVE: %s", pub.Params().Name))
	case ed25519.PublicKey:
		output.WriteString(fmt.Sprintf("Public-Key: (%d bit)\n", len(pub)*8))
		output.WriteString("pub:\n")
		output.WriteString(bytesToHex(pub))
	case *ecdh.PublicKey:
		keyBytes := pub.Bytes()
		output.WriteString(fmt.Sprintf("Public-Key: (%d bit)\n", len(keyBytes)*8))
		output.WriteString("pub:\n")
		output.WriteString(bytesToHex(keyBytes))
	default:
		output.WriteString(fmt.Sprintf("%v", pub))
	}

	return output.String()
}

func wrap(text string, width, indent int) string {
	prefix := strings.Repeat(" ", indent)

	var elems []string
	for _, line := range strings.Split(text, "\n") {
		for {
			if len(line) <= width {
				elems = append(elems, prefix+line)
				break
			}
			elems = append(elems, prefix+line[:width])
			line = line[width:]
		}
	}
	return strings.Join(elems, "\n")
}
