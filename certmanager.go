package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/term"
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
	Children     []*Certificate
}

// KeyPair represents a private key with its hash
type KeyPair struct {
	PublicKeyHash string
	PEMData       string
}

// DatabaseInterface defines the database operations needed by the certificate manager
type DatabaseInterface interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
	Begin() (*sql.Tx, error)
	Close() error
}

// PasswordReader interface for abstracting password input
type PasswordReader interface {
	ReadPassword(prompt string) (string, error)
}

// FileWriter interface for abstracting file operations
type FileWriter interface {
	WriteFile(filename string, data []byte, perm int) error
}

// DefaultPasswordReader implements PasswordReader using terminal input
type DefaultPasswordReader struct{}

func (r *DefaultPasswordReader) ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	passwordBytes, err := term.ReadPassword(0)
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(passwordBytes), nil
}

// DefaultFileWriter implements FileWriter using os.WriteFile
type DefaultFileWriter struct{}

func (w *DefaultFileWriter) WriteFile(filename string, data []byte, perm int) error {
	// In a real implementation, this would use os.WriteFile
	// For now, we'll simulate it
	return nil
}

// CertificateManager handles all certificate operations
type CertificateManager struct {
	db             DatabaseInterface
	passwordReader PasswordReader
	fileWriter     FileWriter
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(db DatabaseInterface) *CertificateManager {
	return &CertificateManager{
		db:             db,
		passwordReader: &DefaultPasswordReader{},
		fileWriter:     &DefaultFileWriter{},
	}
}

// SetPasswordReader sets a custom password reader (useful for testing)
func (cm *CertificateManager) SetPasswordReader(reader PasswordReader) {
	cm.passwordReader = reader
}

// SetFileWriter sets a custom file writer (useful for testing)
func (cm *CertificateManager) SetFileWriter(writer FileWriter) {
	cm.fileWriter = writer
}

// InitializeDatabase creates the necessary database tables
func (cm *CertificateManager) InitializeDatabase() error {
	// Create certificates table
	_, err := cm.db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			serial_number TEXT PRIMARY KEY,
			subject TEXT NOT NULL,
			issuer TEXT NOT NULL,
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			pem_data TEXT NOT NULL,
			key_hash TEXT,
			is_self_signed BOOLEAN NOT NULL,
			is_root BOOLEAN NOT NULL,
			is_ca BOOLEAN NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// Create keys table
	_, err = cm.db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			public_key_hash TEXT PRIMARY KEY,
			pem_data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

// ImportCertificate imports a certificate and optionally its private key
func (cm *CertificateManager) ImportCertificate(certPEM string, keyPEM string) (*Certificate, error) {
	cert, err := cm.parseCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Calculate key hash
	keyHash := cm.calculatePublicKeyHash(cert.X509Cert)

	// Import key if provided
	if keyPEM != "" {
		_, err = cm.db.Exec(`
			INSERT OR REPLACE INTO keys (public_key_hash, pem_data)
			VALUES (?, ?)
		`, keyHash, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to store key: %v", err)
		}
		cert.KeyHash = keyHash
	}

	// Store certificate
	_, err = cm.db.Exec(`
		INSERT OR REPLACE INTO certificates
		(serial_number, subject, issuer, not_before, not_after,
		 pem_data, key_hash, is_self_signed, is_root, is_ca)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.SerialNumber, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter,
		cert.PEMData, cert.KeyHash, cert.IsSelfSigned, cert.IsRoot, cert.IsCA)
	if err != nil {
		return nil, fmt.Errorf("failed to store certificate: %v", err)
	}

	return cert, nil
}

// GetCertificate retrieves a certificate by serial number
func (cm *CertificateManager) GetCertificate(serialNumber string) (*Certificate, error) {
	var cert Certificate
	var keyHash sql.NullString

	err := cm.db.QueryRow(`
		SELECT serial_number, subject, issuer, not_before, not_after,
		       pem_data, key_hash, is_self_signed, is_root, is_ca
		FROM certificates
		WHERE serial_number = ?
	`, serialNumber).Scan(&cert.SerialNumber, &cert.Subject, &cert.Issuer,
		&cert.NotBefore, &cert.NotAfter, &cert.PEMData, &keyHash,
		&cert.IsSelfSigned, &cert.IsRoot, &cert.IsCA)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate with serial %s not found", serialNumber)
		}
		return nil, err
	}

	if keyHash.Valid {
		cert.KeyHash = keyHash.String
	}

	// Parse the X.509 certificate
	parsedCert, err := cm.parseCertificateFromPEM(cert.PEMData)
	if err != nil {
		return nil, err
	}
	cert.X509Cert = parsedCert.X509Cert

	return &cert, nil
}

// GetAllCertificates retrieves all certificates from the database
func (cm *CertificateManager) GetAllCertificates() ([]*Certificate, error) {
	rows, err := cm.db.Query(`
		SELECT serial_number, subject, issuer, not_before, not_after,
		       pem_data, key_hash, is_self_signed, is_root, is_ca
		FROM certificates
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*Certificate
	for rows.Next() {
		cert := &Certificate{}
		var keyHash sql.NullString

		err := rows.Scan(&cert.SerialNumber, &cert.Subject, &cert.Issuer,
			&cert.NotBefore, &cert.NotAfter, &cert.PEMData, &keyHash,
			&cert.IsSelfSigned, &cert.IsRoot, &cert.IsCA)
		if err != nil {
			return nil, err
		}

		if keyHash.Valid {
			cert.KeyHash = keyHash.String
		}

		// Parse the X.509 certificate
		parsedCert, err := cm.parseCertificateFromPEM(cert.PEMData)
		if err != nil {
			continue // Skip certificates that can't be parsed
		}
		cert.X509Cert = parsedCert.X509Cert

		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// BuildCertificateTree builds a hierarchical tree of certificates
func (cm *CertificateManager) BuildCertificateTree(certificates []*Certificate) []*Certificate {
	var roots []*Certificate

	for _, cert := range certificates {
		if cert.IsSelfSigned {
			roots = append(roots, cert)
		} else {
			// Find parent by matching issuer
			parentFound := false
			for _, parent := range certificates {
				if parent.Subject == cert.Issuer {
					parent.Children = append(parent.Children, cert)
					parentFound = true
					break
				}
			}
			// If no parent found, treat as orphan root
			if !parentFound {
				roots = append(roots, cert)
			}
		}
	}

	// Sort certificates
	cm.sortCertificates(roots)
	for _, cert := range certificates {
		cm.sortCertificates(cert.Children)
	}

	return roots
}

// DeleteCertificate deletes a certificate and optionally its key
type DeleteResult struct {
	CertificateDeleted bool
	KeyDeleted         bool
	KeyPreserved       bool
	KeyUsageCount      int
	ChildrenCount      int
	Subject            string
}

func (cm *CertificateManager) DeleteCertificate(serialNumber string, force bool) (*DeleteResult, error) {
	// Load certificate to get details and key hash
	var subject string
	var keyHashPtr sql.NullString
	err := cm.db.QueryRow(`
		SELECT subject, key_hash
		FROM certificates
		WHERE serial_number = ?
	`, serialNumber).Scan(&subject, &keyHashPtr)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate with serial %s not found", serialNumber)
		}
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}

	var keyHash string
	if keyHashPtr.Valid {
		keyHash = keyHashPtr.String
	}

	result := &DeleteResult{
		Subject: subject,
	}

	// Check if certificate has children
	err = cm.db.QueryRow(`
		SELECT COUNT(*)
		FROM certificates
		WHERE issuer = ?
	`, subject).Scan(&result.ChildrenCount)
	if err != nil {
		return nil, fmt.Errorf("failed to check for child certificates: %v", err)
	}

	// Begin transaction for atomic deletion
	tx, err := cm.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Delete the certificate
	certResult, err := tx.Exec("DELETE FROM certificates WHERE serial_number = ?", serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to delete certificate: %v", err)
	}

	rowsAffected, err := certResult.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("failed to get rows affected: %v", err)
	}

	result.CertificateDeleted = rowsAffected > 0

	// Handle associated private key
	if keyHash != "" {
		err = tx.QueryRow(`
			SELECT COUNT(*)
			FROM certificates
			WHERE key_hash = ?
		`, keyHash).Scan(&result.KeyUsageCount)
		if err != nil {
			return nil, fmt.Errorf("failed to check key usage: %v", err)
		}

		if result.KeyUsageCount == 0 {
			// No other certificates use this key, safe to delete
			keyResult, err := tx.Exec("DELETE FROM keys WHERE public_key_hash = ?", keyHash)
			if err != nil {
				return nil, fmt.Errorf("failed to delete private key: %v", err)
			}

			keyRowsAffected, err := keyResult.RowsAffected()
			if err != nil {
				return nil, fmt.Errorf("failed to get key deletion rows affected: %v", err)
			}

			result.KeyDeleted = keyRowsAffected > 0
		} else {
			result.KeyPreserved = true
		}
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return result, nil
}

// ExportCertificateText exports certificate in human-readable format
func (cm *CertificateManager) ExportCertificateText(serialNumber string) (string, error) {
	cert, err := cm.GetCertificate(serialNumber)
	if err != nil {
		return "", err
	}

	return cm.generateCertificateText(cert), nil
}

// ExportCertificateToFile exports certificate to a file
func (cm *CertificateManager) ExportCertificateToFile(serialNumber, filename string) error {
	text, err := cm.ExportCertificateText(serialNumber)
	if err != nil {
		return err
	}

	return cm.fileWriter.WriteFile(filename, []byte(text), 0644)
}

// ExportPrivateKey exports the private key for a certificate
func (cm *CertificateManager) ExportPrivateKey(serialNumber string) (string, error) {
	cert, err := cm.GetCertificate(serialNumber)
	if err != nil {
		return "", err
	}

	if cert.KeyHash == "" {
		return "", fmt.Errorf("no private key associated with certificate %s", serialNumber)
	}

	var keyData string
	err = cm.db.QueryRow("SELECT pem_data FROM keys WHERE public_key_hash = ?", cert.KeyHash).Scan(&keyData)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %v", err)
	}

	return keyData, nil
}

// ExportPrivateKeyToFile exports private key to a file
func (cm *CertificateManager) ExportPrivateKeyToFile(serialNumber, filename string) error {
	keyData, err := cm.ExportPrivateKey(serialNumber)
	if err != nil {
		return err
	}

	return cm.fileWriter.WriteFile(filename, []byte(keyData), 0600)
}

// ReencryptPrivateKey changes the password of a private key
func (cm *CertificateManager) ReencryptPrivateKey(serialNumber, currentPassword, newPassword string) error {
	cert, err := cm.GetCertificate(serialNumber)
	if err != nil {
		return err
	}

	if cert.KeyHash == "" {
		return fmt.Errorf("no private key associated with certificate %s", serialNumber)
	}

	// Load current key data
	var keyData string
	err = cm.db.QueryRow("SELECT pem_data FROM keys WHERE public_key_hash = ?", cert.KeyHash).Scan(&keyData)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
	}

	// Decrypt with current password
	privateKey, err := cm.loadPrivateKeyFromPEM(keyData, currentPassword)
	if err != nil {
		return fmt.Errorf("failed to decrypt private key (wrong password?): %v", err)
	}

	// Re-encrypt with new password
	newKeyData, err := cm.encryptPrivateKey(privateKey, newPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key with new password: %v", err)
	}

	// Update in database
	_, err = cm.db.Exec("UPDATE keys SET pem_data = ? WHERE public_key_hash = ?", newKeyData, cert.KeyHash)
	if err != nil {
		return fmt.Errorf("failed to update private key: %v", err)
	}

	return nil
}

// CreateRootCA creates a new root CA certificate
type CreateRootCARequest struct {
	CommonName string
	KeySize    int
	ValidDays  int
	Password   string
}

func (cm *CertificateManager) CreateRootCA(req *CreateRootCARequest) (*Certificate, error) {
	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Generate certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: req.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, req.ValidDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate (self-signed)
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Convert to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encrypt and store private key
	keyPEM, err := cm.encryptPrivateKey(privateKey, req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %v", err)
	}

	// Import the certificate
	return cm.ImportCertificate(string(certPEM), keyPEM)
}

// Helper methods

func (cm *CertificateManager) calculatePublicKeyHash(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

func (cm *CertificateManager) parseCertificateFromPEM(pemData string) (*Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM data")
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
		PEMData:      pemData,
		IsSelfSigned: x509Cert.Subject.String() == x509Cert.Issuer.String(),
		IsRoot:       x509Cert.IsCA && x509Cert.Subject.String() == x509Cert.Issuer.String(),
		IsCA:         x509Cert.IsCA,
		X509Cert:     x509Cert,
	}

	return cert, nil
}

func (cm *CertificateManager) generateCertificateText(cert *Certificate) string {
	var builder strings.Builder

	builder.WriteString("Certificate:\n")
	builder.WriteString("    Data:\n")
	builder.WriteString(fmt.Sprintf("        Version: %d\n", cert.X509Cert.Version))
	builder.WriteString(fmt.Sprintf("        Serial Number: %s\n", cert.SerialNumber))
	builder.WriteString("    Signature Algorithm: " + cert.X509Cert.SignatureAlgorithm.String() + "\n")
	builder.WriteString("        Issuer: " + cert.Issuer + "\n")
	builder.WriteString("        Validity:\n")
	builder.WriteString(fmt.Sprintf("            Not Before: %s\n", cert.NotBefore.Format("Jan 2 15:04:05 2006 MST")))
	builder.WriteString(fmt.Sprintf("            Not After:  %s\n", cert.NotAfter.Format("Jan 2 15:04:05 2006 MST")))
	builder.WriteString("        Subject: " + cert.Subject + "\n")

	if cert.IsCA {
		builder.WriteString("        CA: TRUE\n")
	}

	if len(cert.X509Cert.DNSNames) > 0 {
		builder.WriteString("        Subject Alternative Name:\n")
		for _, dns := range cert.X509Cert.DNSNames {
			builder.WriteString(fmt.Sprintf("            DNS:%s\n", dns))
		}
	}

	builder.WriteString("\n" + cert.PEMData)

	return builder.String()
}

func (cm *CertificateManager) sortCertificates(certificates []*Certificate) {
	sort.Slice(certificates, func(i, j int) bool {
		return certificates[i].Subject < certificates[j].Subject
	})
}

func (cm *CertificateManager) loadPrivateKeyFromPEM(pemData, password string) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

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

	// Try parsing as different key types
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func (cm *CertificateManager) encryptPrivateKey(privateKey any, password string) (string, error) {
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
