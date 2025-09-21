package dblib

import (
	"context"
	"database/sql"
)

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func New(db *sql.DB) *Queries {
	return &Queries{db: db}
}

type Queries struct {
	db DBTX
}

func (q *Queries) Begin() *Queries {
	tx, err := q.db.(*sql.DB).Begin()
	if err != nil {
		panic(err)
	}
	return &Queries{
		db: tx,
	}
}

func (q *Queries) Commit() error {
	return q.db.(*sql.Tx).Commit()
}

func (q *Queries) Rollback() error {
	return q.db.(*sql.Tx).Rollback()
}
