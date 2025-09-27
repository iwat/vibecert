package application

import (
	"testing"

	"github.com/iwat/vibecert/internal/domain"
)

func TestCertificateManager_BuildCertificateTree(t *testing.T) {
	app, db, _, _, _, err := createTestApp(t)
	if err != nil {
		t.Fatalf("Failed to create test certificate manager: %v", err)
	}

	// Create mock certificates with parent-child relationships
	_, err = db.CreateCertificate(t.Context(), &domain.Certificate{
		SerialNumber: "root123",
		SubjectDN:    "CN=Root CA",
		IssuerDN:     "CN=Root CA",
		IsCA:         true,
	})
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	_, err = db.CreateCertificate(t.Context(), &domain.Certificate{
		SerialNumber: "intermediate456",
		SubjectDN:    "CN=Intermediate CA",
		IssuerDN:     "CN=Root CA",
		IsCA:         true,
	})
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	_, err = db.CreateCertificate(t.Context(), &domain.Certificate{
		SerialNumber: "leaf789",
		SubjectDN:    "CN=Leaf Certificate",
		IssuerDN:     "CN=Intermediate CA",
		IsCA:         false,
	})
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	_, err = db.CreateCertificate(t.Context(), &domain.Certificate{
		SerialNumber: "orphan999",
		SubjectDN:    "CN=Orphan Certificate",
		IssuerDN:     "CN=Missing CA",
		IsCA:         false,
	})

	// Build tree
	tree := app.BuildCertificateTree(t.Context())

	// Verify tree structure
	if len(tree) != 2 { // Root cert and orphan cert should be roots
		t.Errorf("Expected 2 root certificates, got %d", len(tree))
	}

	// Find root certificate in tree
	var foundRoot *CertificateNode
	for _, cert := range tree {
		if cert.Certificate.SerialNumber == "root123" {
			foundRoot = cert
			break
		}
	}

	if foundRoot == nil {
		t.Fatalf("Root certificate not found in tree")
	}

	// Verify root has intermediate as child
	if len(foundRoot.Children) != 1 {
		t.Errorf("Expected root to have 1 child, got %d", len(foundRoot.Children))
	}

	if foundRoot.Children[0].Certificate.SerialNumber != "intermediate456" {
		t.Errorf("Expected intermediate as child of root")
	}

	// Verify intermediate has leaf as child
	intermediate := foundRoot.Children[0]
	if len(intermediate.Children) != 1 {
		t.Errorf("Expected intermediate to have 1 child, got %d", len(intermediate.Children))
	}

	if intermediate.Children[0].Certificate.SerialNumber != "leaf789" {
		t.Errorf("Expected leaf as child of intermediate")
	}
}
