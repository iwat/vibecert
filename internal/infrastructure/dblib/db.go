package dblib

import (
	"context"
	"database/sql"
)

type DBTX interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type TxManager interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

func New(db DBTX) *Queries {
	return &Queries{db: db}
}

type Queries struct {
	db DBTX
}

func (q *Queries) Begin(ctx context.Context) *TransactionalQueries {
	tx, err := q.db.(TxManager).BeginTx(ctx, nil)
	if err != nil {
		panic(err)
	}
	return &TransactionalQueries{
		&Queries{db: tx},
	}
}

type TransactionalQueries struct {
	*Queries
}

func (q *TransactionalQueries) Commit() error {
	return q.db.(*sql.Tx).Commit()
}

func (q *TransactionalQueries) Rollback() error {
	return q.db.(*sql.Tx).Rollback()
}
