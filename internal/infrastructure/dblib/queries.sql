-- name: CreateCertificate :one
INSERT INTO certificate (
    serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
RETURNING id;

-- name: CertificateByID :one
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
WHERE id = ?;

-- name: CertificateByIssuerAndSerialNumber :one
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
WHERE issuer_dn = ? AND serial_number = ?;

-- name: CertificatesByIssuerAndAuthorityKeyID :many
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
WHERE issuer_dn = ? AND authority_key_id = ?;

-- name: CertificatesByPublicKeyHash :many
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate
WHERE public_key_hash = ?;

-- name: AllCertificates :many
SELECT
    id, serial_number, subject_dn, issuer_dn, not_before, not_after,
    signature_algo, subject_key_id, authority_key_id,
    is_ca, pem_data, public_key_hash
FROM certificate;

-- name: DeleteCertificate :exec
DELETE FROM certificate WHERE id = ?;

-- name: CreateKey :one
INSERT OR REPLACE INTO key (
    public_key_hash, key_type, key_size, pem_data
) VALUES (?, ?, ?, ?)
RETURNING id;

-- name: KeyByID :one
SELECT
    id, public_key_hash, key_type, key_size, pem_data
FROM key
WHERE id = ?;

-- name: KeyByPublicKeyHash :one
SELECT
    id, public_key_hash, key_type, key_size, pem_data
FROM key
WHERE public_key_hash = ?;

-- name: AllKeys :many
SELECT
    id, public_key_hash, key_type, key_size, pem_data
FROM key;

-- name: UpdateKeyPEM :exec
UPDATE key SET pem_data = ? WHERE id = ?;

-- name: DeleteKey :exec
DELETE FROM key WHERE id = ?;
