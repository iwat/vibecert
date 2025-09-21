package application

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/iwat/vibecert/internal/infrastructure/dblib"

	_ "github.com/mattn/go-sqlite3"
)

// Test helper to create in-memory SQLite database
func createTestDatabase() (*dblib.Queries, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	queries := dblib.New(db)
	queries.InitializeDatabase(context.TODO())
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

func (r *MockPasswordReader) ReadPassword(prompt string) (string, error) {
	if len(r.passwords) == 0 {
		return "", fmt.Errorf("no more mock passwords available")
	}
	password := r.passwords[0]
	r.passwords = r.passwords[1:]
	return password, nil
}

func TestPasswordReader_Mock(t *testing.T) {
	reader := NewMockPasswordReader("password1", "password2")

	// Test first password
	pwd1, err := reader.ReadPassword("Enter password: ")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if pwd1 != "password1" {
		t.Errorf("Expected 'password1', got '%s'", pwd1)
	}

	// Test second password
	pwd2, err := reader.ReadPassword("Enter password: ")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if pwd2 != "password2" {
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
