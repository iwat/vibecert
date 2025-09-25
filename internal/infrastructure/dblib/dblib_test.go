package dblib

import (
	"database/sql"
	"testing"

	"github.com/iwat/vibecert/internal/domain"

	_ "github.com/mattn/go-sqlite3"
)

func TestCertificate(t *testing.T) {
	q, err := createTestDatabase(t)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	cert, err := q.CreateCertificate(t.Context(), &domain.Certificate{ID: -1})
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	if cert == nil {
		t.Fatalf("Certificate is nil")
	}
	if cert.ID < 0 {
		t.Fatalf("Certificate is still negative")
	}

	readBackCert, err := q.CertificateByID(t.Context(), cert.ID)
	if err != nil {
		t.Fatalf("Failed to read back certificate: %v", err)
	}
	if readBackCert == nil {
		t.Fatalf("Read back certificate is nil")
	}

	tx := q.Begin(t.Context())
	err = tx.DeleteCertificate(t.Context(), readBackCert.ID)
	if err != nil {
		t.Fatalf("Failed to delete certificate: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Failed to rollback transaction: %v", err)
	}

	readBackCertAgain, err := q.CertificateByID(t.Context(), cert.ID)
	if err != nil {
		t.Fatalf("Failed to read back certificate: %v", err)
	}
	if readBackCertAgain == nil {
		t.Fatalf("Read back certificate is nil")
	}

	tx = q.Begin(t.Context())
	err = tx.DeleteCertificate(t.Context(), readBackCert.ID)
	if err != nil {
		t.Fatalf("Failed to delete certificate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	_, err = q.CertificateByID(t.Context(), cert.ID)
	if err != sql.ErrNoRows {
		t.Fatalf("CertificateByID should have failed, entry deleted: %v", err)
	}
}

// Test helper to create in-memory SQLite database
func createTestDatabase(t *testing.T) (*Queries, error) {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	New(db).InitializeDatabase(t.Context())
	queries := New(db)
	return queries, nil
}
