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
	UNIQUE(issuer_dn, serial_number),
	UNIQUE(public_key_hash)
);

CREATE TABLE IF NOT EXISTS key (
	id INTEGER PRIMARY KEY,
    public_key_hash TEXT NOT NULL UNIQUE,
    key_type TEXT NOT NULL,
    key_size INTEGER NOT NULL,
	pem_data TEXT NOT NULL
);
