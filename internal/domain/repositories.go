package domain

import (
	"database/sql"
	"fmt"
)

// DatabaseInterface defines the database operations needed by the repositories
type DatabaseInterface interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
	Begin() (*sql.Tx, error)
	Close() error
}

// CertificateRepository handles all certificate operations
type CertificateRepository struct {
	db DatabaseInterface
}

// Initialize creates the necessary database tables
func (cr *CertificateRepository) Initialize() error {
	// Create certificates table
	_, err := cr.db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			serial_number TEXT PRIMARY KEY,
			subject TEXT NOT NULL,
			issuer TEXT NOT NULL,
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			pem_data TEXT NOT NULL,
			key_hash TEXT NOT NULL,
			is_self_signed BOOLEAN NOT NULL,
			is_root BOOLEAN NOT NULL,
			is_ca BOOLEAN NOT NULL
		)
	`)
	return err
}

// Save stores the given certificate in the database
func (cr *CertificateRepository) Save(cert *Certificate) error {
	_, err := cr.db.Exec(`
		INSERT OR REPLACE INTO certificates
		(serial_number, subject, issuer, not_before, not_after,
		 pem_data, key_hash, is_self_signed, is_root, is_ca)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.SerialNumber, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter,
		cert.PEMData, cert.KeyHash, cert.IsSelfSigned, cert.IsRoot, cert.IsCA)
	if err != nil {
		return fmt.Errorf("failed to store certificate: %v", err)
	}

	return nil
}

// KeyRepository handles all key operations
type KeyRepository struct {
	db DatabaseInterface
}

// Initialize creates the necessary database tables
func (kr *KeyRepository) Initialize() error {
	// Create keys table
	_, err := kr.db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			public_key_hash TEXT PRIMARY KEY,
			pem_data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}
