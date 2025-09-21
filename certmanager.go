package main

import (
	"database/sql"
	"fmt"
)

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
