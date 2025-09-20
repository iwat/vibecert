package application

import (
	"context"
	"database/sql"

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
