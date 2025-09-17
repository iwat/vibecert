package domain

import (
	"database/sql"
	"fmt"
)

// CertificateRepository handles all certificate operations
type CertificateRepository struct {
	db sql.DB
}

// Initialize creates the necessary database tables
func (cr *CertificateRepository) Initialize() error {
	// Create certificates table
	_, err := cr.db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
			id INTEGER PRIMARY KEY,
			serial_number TEXT NOT NULL,
			subject_dn TEXT NOT NULL,
			issuer_dn TEXT NOT NULL,
			not_before DATETIME NOT NULL,
			not_after DATETIME NOT NULL,
			signature_algo TEXT NOT NULL,
			subject_key_id TEXT NOT NULL,
			authority_key_id TEXT,
			is_ca INTEGER NOT NULL,
			pem_data TEXT NOT NULL,
			public_key_hash TEXT NOT NULL,
			UNIQUE(issuer_dn, serial_number)
		)
	`)
	return err
}

// Save stores the given certificate in the database
func (cr *CertificateRepository) Save(cert *Certificate) error {
	tx, err := cr.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	if cert.ID == -1 {
		row := tx.QueryRow("SELECT id FROM certificates WHERE issuer_dn = ? AND serial_number = ?",
			cert.IssuerDN, cert.SerialNumber)
		if row != nil {
			row.Scan(&cert.ID)
		}
	}

	if cert.ID == -1 {
		_, err = tx.Exec(`
			INSERT INTO certificates
			(serial_number, subject_dn, issuer_dn, not_before, not_after,
			 signature_algo, subject_key_id, authority_key_id,
			 is_ca, pem_data, public_key_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, cert.SerialNumber, cert.SubjectDN, cert.IssuerDN, cert.NotBefore, cert.NotAfter,
			cert.SignatureAlgorithm, cert.SubjectKeyID, cert.AuthorityKeyID,
			cert.IsCA, cert.PEMData, cert.PublicKeyHash)
		if err != nil {
			return fmt.Errorf("failed to store certificate: %v", err)
		}
	} else {
		_, err = tx.Exec(`
			INSERT OR REPLACE INTO certificates
			(id, serial_number, subject_dn, issuer_dn, not_before, not_after,
			 signature_algo, subject_key_id, authority_key_id,
			 is_ca, pem_data, public_key_hash)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, cert.ID, cert.SerialNumber, cert.SubjectDN, cert.IssuerDN, cert.NotBefore, cert.NotAfter,
			cert.SignatureAlgorithm, cert.SubjectKeyID, cert.AuthorityKeyID,
			cert.IsCA, cert.PEMData, cert.PublicKeyHash)
		if err != nil {
			return fmt.Errorf("failed to store certificate: %v", err)
		}
	}
	return tx.Commit()
}

// KeyRepository handles all key operations
type KeyRepository struct {
	db sql.DB
}

// Initialize creates the necessary database tables
func (kr *KeyRepository) Initialize() error {
	// Create keys table
	_, err := kr.db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			id INTEGER PRIMARY KEY,
		    public_key_hash TEXT NOT NULL UNIQUE,
		    key_type TEXT NOT NULL,
		    key_size INTEGER NOT NULL,
			pem_data TEXT NOT NULL
		)
	`)
	return err
}

func (kr *KeyRepository) Save(key *KeyPair) error {
	tx, err := kr.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %v", err)
	}

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO keys
		(id, public_key_hash, key_type, key_size, pem_data)
		VALUES (?, ?, ?, ?, ?)
	`, key.ID, key.PublicKeyHash, key.KeyType, key.KeySize, key.PEMData)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to store key: %v", err)
	}

	return tx.Commit()
}
