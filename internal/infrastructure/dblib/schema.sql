CREATE TABLE IF NOT EXISTS certificate (
	id INTEGER PRIMARY KEY,
	serial_number TEXT NOT NULL,
	subject_dn TEXT NOT NULL,
	issuer_dn TEXT NOT NULL,
	not_before DATETIME NOT NULL,
	not_after DATETIME NOT NULL,
	signature_algo TEXT NOT NULL,
	subject_key_id TEXT NOT NULL,
	authority_key_id TEXT,
	is_ca INTEGER NOT NULL,
	pem_data TEXT NOT NULL,
	public_key_hash TEXT NOT NULL,
	UNIQUE(serial_number, issuer_dn)
);

CREATE INDEX IF NOT EXISTS idx_certificate_public_key_hash ON certificate (public_key_hash);
CREATE INDEX IF NOT EXISTS idx_certificate_issuer_dn_authority_key_id ON certificate (issuer_dn, authority_key_id);

CREATE TABLE IF NOT EXISTS key (
	id INTEGER PRIMARY KEY,
    public_key_hash TEXT NOT NULL UNIQUE,
    key_spec TEXT NOT NULL,
	pem_data TEXT NOT NULL
);
