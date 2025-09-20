package dblib

import (
	"context"

	"github.com/iwat/vibecert/internal/domain"
)

const allCertificates = `-- name: AllCertificated :many
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
`

func (q *Queries) AllCertificates(ctx context.Context) ([]*domain.Certificate, error) {
	rows, err := q.db.QueryContext(ctx, allCertificates)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*domain.Certificate
	for rows.Next() {
		var i domain.Certificate
		if err := rows.Scan(
			&i.ID,
			&i.SerialNumber,
			&i.SubjectDN,
			&i.IssuerDN,
			&i.NotBefore,
			&i.NotAfter,
			&i.SignatureAlgorithm,
			&i.SubjectKeyID,
			&i.AuthorityKeyID,
			&i.IsCA,
			&i.PEMData,
			&i.PublicKeyHash,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const certificateByID = `-- name: CertificateByID :one
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
WHERE id = ?
`

func (q *Queries) CertificateByID(ctx context.Context, id int64) (*domain.Certificate, error) {
	row := q.db.QueryRowContext(ctx, certificateByID, id)
	var i domain.Certificate
	err := row.Scan(
		&i.ID,
		&i.SerialNumber,
		&i.SubjectDN,
		&i.IssuerDN,
		&i.NotBefore,
		&i.NotAfter,
		&i.SignatureAlgorithm,
		&i.SubjectKeyID,
		&i.AuthorityKeyID,
		&i.IsCA,
		&i.PEMData,
		&i.PublicKeyHash,
	)
	return &i, err
}

const certificateByIssuerAndSerialNumber = `-- name: CertificateByIssuerAndSerialNumber :one
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
WHERE issuer_dn = ? AND serial_number = ?
`

type CertificateByIssuerAndSerialNumberParams struct {
	IssuerDN     string
	SerialNumber string
}

func (q *Queries) CertificateByIssuerAndSerialNumber(ctx context.Context, arg CertificateByIssuerAndSerialNumberParams) (*domain.Certificate, error) {
	row := q.db.QueryRowContext(ctx, certificateByIssuerAndSerialNumber, arg.IssuerDN, arg.SerialNumber)
	var i domain.Certificate
	err := row.Scan(
		&i.ID,
		&i.SerialNumber,
		&i.SubjectDN,
		&i.IssuerDN,
		&i.NotBefore,
		&i.NotAfter,
		&i.SignatureAlgorithm,
		&i.SubjectKeyID,
		&i.AuthorityKeyID,
		&i.IsCA,
		&i.PEMData,
		&i.PublicKeyHash,
	)
	return &i, err
}

const certificateByPublicKeyHash = `-- name: CertificateByPublicKeyHash :many
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
WHERE public_key_hash = ?
`

func (q *Queries) CertificateByPublicKeyHash(ctx context.Context, publicKeyHash string) ([]*domain.Certificate, error) {
	rows, err := q.db.QueryContext(ctx, certificateByPublicKeyHash, publicKeyHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*domain.Certificate
	for rows.Next() {
		var i domain.Certificate
		if err := rows.Scan(
			&i.ID,
			&i.SerialNumber,
			&i.SubjectDN,
			&i.IssuerDN,
			&i.NotBefore,
			&i.NotAfter,
			&i.SignatureAlgorithm,
			&i.SubjectKeyID,
			&i.AuthorityKeyID,
			&i.IsCA,
			&i.PEMData,
			&i.PublicKeyHash,
		); err != nil {
			return nil, err
		}
		items = append(items, &i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const createCertificate = `-- name: CreateCertificate :one
INSERT INTO certificate (
    serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING id, serial_number, subject_dn, issuer_dn, not_before, not_after, signature_algo, subject_key_id, authority_key_id, is_ca, pem_data, public_key_hash
`

func (q *Queries) CreateCertificate(ctx context.Context, arg *domain.Certificate) (*domain.Certificate, error) {
	row := q.db.QueryRowContext(ctx, createCertificate,
		arg.SerialNumber,
		arg.SubjectDN,
		arg.IssuerDN,
		arg.NotBefore,
		arg.NotAfter,
		arg.SignatureAlgorithm,
		arg.SubjectKeyID,
		arg.AuthorityKeyID,
		arg.IsCA,
		arg.PEMData,
		arg.PublicKeyHash,
	)
	var i domain.Certificate
	err := row.Scan(
		&i.ID,
		&i.SerialNumber,
		&i.SubjectDN,
		&i.IssuerDN,
		&i.NotBefore,
		&i.NotAfter,
		&i.SignatureAlgorithm,
		&i.SubjectKeyID,
		&i.AuthorityKeyID,
		&i.IsCA,
		&i.PEMData,
		&i.PublicKeyHash,
	)
	return &i, err
}

const createKey = `-- name: CreateKey :one
INSERT OR REPLACE INTO key (
    public_key_hash, key_type, key_size, pem_data
) VALUES (?, ?, ?, ?)
RETURNING id, public_key_hash, key_type, key_size, pem_data
`

func (q *Queries) CreateKey(ctx context.Context, arg *domain.KeyPair) (*domain.KeyPair, error) {
	row := q.db.QueryRowContext(ctx, createKey,
		arg.PublicKeyHash,
		arg.KeyType,
		arg.KeySize,
		arg.PEMData,
	)
	var i domain.KeyPair
	err := row.Scan(
		&i.ID,
		&i.PublicKeyHash,
		&i.KeyType,
		&i.KeySize,
		&i.PEMData,
	)
	return &i, err
}

const keyByID = `-- name: KeyByID :one
SELECT
    id, public_key_hash, key_type, key_size, pem_data
FROM key
WHERE id = ?
`

func (q *Queries) KeyByID(ctx context.Context, id int) (*domain.KeyPair, error) {
	row := q.db.QueryRowContext(ctx, keyByID, id)
	var i domain.KeyPair
	err := row.Scan(
		&i.ID,
		&i.PublicKeyHash,
		&i.KeyType,
		&i.KeySize,
		&i.PEMData,
	)
	return &i, err
}

const keyByPublicKeyHash = `-- name: KeyByPublicKeyHash :one
SELECT
    id, public_key_hash, key_type, key_size, pem_data
FROM key
WHERE public_key_hash = ?
`

func (q *Queries) KeyByPublicKeyHash(ctx context.Context, publicKeyHash string) (*domain.KeyPair, error) {
	row := q.db.QueryRowContext(ctx, keyByPublicKeyHash, publicKeyHash)
	var i domain.KeyPair
	err := row.Scan(
		&i.ID,
		&i.PublicKeyHash,
		&i.KeyType,
		&i.KeySize,
		&i.PEMData,
	)
	return &i, err
}

const updateKeyPEM = `-- name: UpdateKeyPEM :exec
UPDATE key SET pem_data = ? WHERE id = ?
`

func (q *Queries) UpdateKeyPEM(ctx context.Context, id int, pemData string) error {
	_, err := q.db.ExecContext(ctx, updateKeyPEM, pemData, id)
	return err
}
