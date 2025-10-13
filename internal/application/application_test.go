package application

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/iwat/vibecert/internal/domain"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"

	_ "github.com/mattn/go-sqlite3"
)

func TestCreateRootCA(t *testing.T) {
	app, _, passwordReader, _, _, err := createTestApp(t)
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}

	passwordReader.passwords = []string{"secret", "secret"}
	cert, key, err := app.CreateCertificate(t.Context(), &CreateCertificateRequest{
		IssuerCertificateID: SelfSignedCertificateID,
		SubjectKeyID:        NewSubjectKeyID,
		CommonName:          "test",
		KeySize:             2048,
		ValidDays:           3650,
	})
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}
	if cert == nil {
		t.Fatal("Root CA should not be nil")
	}
	if key == nil {
		t.Fatal("Root CA key pair should not be nil")
	}
}

func TestCreateIntermediateCA(t *testing.T) {
	app, _, passwordReader, _, _, err := createTestApp(t)
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}

	passwordReader.passwords = []string{"root-secret", "root-secret"}
	rootCert, _, err := app.CreateCertificate(t.Context(), &CreateCertificateRequest{
		IssuerCertificateID: SelfSignedCertificateID,
		SubjectKeyID:        NewSubjectKeyID,
		CommonName:          "test root",
		KeySize:             2048,
		ValidDays:           3650,
		IsCA:                true,
	})

	passwordReader.passwords = []string{"root-secret", "intermediate-secret", "intermediate-secret"}
	cert, key, err := app.CreateCertificate(t.Context(), &CreateCertificateRequest{
		IssuerCertificateID: rootCert.ID,
		SubjectKeyID:        NewSubjectKeyID,
		CommonName:          "test intermediate",
		KeySize:             2048,
		ValidDays:           3650,
		IsCA:                true,
	})
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}
	if cert == nil {
		t.Fatal("Intermediate CA should not be nil")
	}
	if key == nil {
		t.Fatal("Intermediate CA key pair should not be nil")
	}
}

func TestDeleteCertificate_Cascade(t *testing.T) {
	app, db, _, _, _, err := createTestApp(t)
	if err != nil {
		t.Fatalf("Failed to create test app: %v", err)
	}

	rootCert, err := db.CreateCertificate(t.Context(), &domain.Certificate{
		SerialNumber: "R01",
		IssuerDN:     "Root",
		SubjectDN:    "Root",
		SubjectKeyID: "RRR",
	})
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}
	if rootCert == nil {
		t.Fatal("Root CA should not be nil")
	}

	intermediateCert, err := db.CreateCertificate(t.Context(), &domain.Certificate{
		SerialNumber:   "I01",
		IssuerDN:       "Root",
		SubjectDN:      "Intermediate",
		SubjectKeyID:   "III",
		AuthorityKeyID: "RRR",
	})
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}
	if intermediateCert == nil {
		t.Fatal("Intermediate CA should not be nil")
	}

	// Test deleting the root CA
	deleteResult, err := app.DeleteCertificate(t.Context(), rootCert.ID, true)
	if err != nil {
		t.Fatalf("Failed to delete root CA: %v", err)
	}
	if deleteResult == nil {
		t.Fatal("Delete result should not be nil")
	}
	if deleteResult.ChildrenCount != 1 {
		t.Fatalf("Expected 1 extra child(ren) to be deleted, got %d", deleteResult.ChildrenCount)
	}
}

// Test helper to create test key manager with real database
func createTestApp(t *testing.T) (*App, *dblib.Queries, *MockPasswordReader, *MockFileReader, *MockFileWriter, error) {
	t.Helper()

	db, err := createTestDatabase(t)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	passwordReader := NewMockPasswordReader()
	fileReader := NewMockFileReader()
	fileWriter := NewMockFileWriter()
	confirmer := NewMockConfirmer()

	return NewApp(db, passwordReader, fileReader, fileWriter, confirmer), db, passwordReader, fileReader, fileWriter, nil
}

// Test helper to create in-memory SQLite database
func createTestDatabase(t *testing.T) (*dblib.Queries, error) {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	dblib.New(db).InitializeDatabase(t.Context())
	queries := dblib.New(db)
	return queries, nil
}

type MockPasswordReader struct {
	passwords []string
}

func NewMockPasswordReader(passwords ...string) *MockPasswordReader {
	return &MockPasswordReader{
		passwords: passwords,
	}
}

func (r *MockPasswordReader) ReadPassword(prompt string) ([]byte, error) {
	if len(r.passwords) == 0 {
		return nil, fmt.Errorf("no more mock passwords available")
	}
	password := r.passwords[0]
	r.passwords = r.passwords[1:]
	return []byte(password), nil
}

func TestPasswordReader_Mock(t *testing.T) {
	reader := NewMockPasswordReader("password1", "password2")

	// Test first password
	pwd1, err := reader.ReadPassword("Enter password: ")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if string(pwd1) != "password1" {
		t.Errorf("Expected 'password1', got '%s'", pwd1)
	}

	// Test second password
	pwd2, err := reader.ReadPassword("Enter password: ")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if string(pwd2) != "password2" {
		t.Errorf("Expected 'password2', got '%s'", pwd2)
	}

	// Test exhausted passwords
	_, err = reader.ReadPassword("Enter password: ")
	if err == nil {
		t.Errorf("Expected error when no more passwords available")
	}
}

type MockFileWriter struct {
	files map[string][]byte
}

func NewMockFileWriter() *MockFileWriter {
	return &MockFileWriter{
		files: make(map[string][]byte),
	}
}

func (w *MockFileWriter) WriteFile(filename string, data []byte, perm int) error {
	w.files[filename] = data
	return nil
}

func (w *MockFileWriter) GetWrittenFile(filename string) ([]byte, bool) {
	data, exists := w.files[filename]
	return data, exists
}

func TestFileWriter_Mock(t *testing.T) {
	writer := NewMockFileWriter()

	filename := "test.txt"
	content := []byte("test content")

	// Write file
	err := writer.WriteFile(filename, content, 0644)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Read file
	data, exists := writer.GetWrittenFile(filename)
	if !exists {
		t.Errorf("Expected file to exist")
	}

	if string(data) != string(content) {
		t.Errorf("Expected content '%s', got '%s'", string(content), string(data))
	}

	// Check non-existent file
	_, exists = writer.GetWrittenFile("nonexistent.txt")
	if exists {
		t.Errorf("Expected file to not exist")
	}
}

type MockFileReader struct {
	files map[string][]byte
}

func NewMockFileReader() *MockFileReader {
	return &MockFileReader{
		files: make(map[string][]byte),
	}
}

func (r *MockFileReader) ReadFile(filename string) ([]byte, error) {
	data, exists := r.files[filename]
	if !exists {
		return nil, fmt.Errorf("file not found")
	}
	return data, nil
}

type MockConfirmer struct{}

func NewMockConfirmer() *MockConfirmer {
	return &MockConfirmer{}
}

func (c *MockConfirmer) Confirm(prompt string) bool {
	return true
}
