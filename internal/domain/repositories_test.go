package domain

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// Test helper to create in-memory SQLite database
func createTestDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	return db, nil
}
