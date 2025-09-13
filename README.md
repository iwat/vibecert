# VibeCert - SQLite Certificate Management System

VibeCert is a certificate and private key management system that uses SQLite for storage. It provides a modern approach to certificate lifecycle management with advanced querying capabilities.

## Features

- **SQLite Database Storage**: All certificates and keys are stored in a SQLite database for efficient querying and management
- **Certificate Chain Visualization**: Display certificate dependency trees
- **Import/Export Operations**: Import existing certificates and keys, export in various formats
- **Key Management**: Secure private key storage with password-based encryption
- **PKCS#12 Export**: Export certificates and keys as PKCS#12 files for easy deployment
- **Human-Readable Certificate Export**: Export certificate details similar to `openssl x509 -text`

## Database Schema

The system uses two main tables:

### Certificates Table
- `serial_number` (PRIMARY KEY): Certificate serial number
- `subject`: Certificate subject DN
- `issuer`: Certificate issuer DN
- `not_before`: Certificate validity start date
- `not_after`: Certificate validity end date
- `pem_data`: Complete X.509 certificate in PEM format
- `key_hash`: SHA256 hash of the public key (links to keys table)
- `is_self_signed`: Boolean indicating if certificate is self-signed
- `is_root`: Boolean indicating if certificate is a root CA
- `is_ca`: Boolean indicating if certificate is a CA

### Keys Table
- `public_key_hash` (PRIMARY KEY): SHA256 hash of the public key
- `pem_data`: Encrypted private key in PEM format

## Commands

### Certificate Tree View
```bash
vibecert tree
```
Displays a hierarchical view of all certificates showing their relationships and key availability.

### Import Operations
```bash
# Import certificate with private key
vibecert import --cert path/to/cert.pem --key path/to/key.pem

# Import certificate only
vibecert import --cert path/to/cert.pem
```

### Export Operations
```bash
# Export certificate with human-readable content
vibecert export-cert --serial <serial_number> [--output filename.txt]

# Export private key
vibecert export-key --serial <serial_number> [--output filename.key]

# Export as PKCS#12
vibecert export-pkcs12 --serial <serial_number> [--output filename.p12] [--name "Friendly Name"]
```

### Key Management
```bash
# Change private key password
vibecert reencrypt-key --serial <serial_number>
```

### Certificate Creation
```bash
# Create root CA certificate
vibecert create-root --cn "Root CA Name" [--key-size 4096] [--valid-days 3650]

# Create intermediate CA certificate
vibecert create-intermediate --cn "Intermediate CA" --ca-serial <parent_serial> [--key-size 4096] [--valid-days 1825]

# Create end-entity certificate
vibecert create-leaf --cn "Server Name" --ca-serial <parent_serial> [--san-dns "example.com,*.example.com"] [--key-size 4096] [--valid-days 365]
```

## Migration from File-Based Storage

If you have existing certificates stored in the `data/certs` and `data/keys` directories, you can import them:

```bash
# Import all existing certificates with keys
for cert in data/certs/*.crt; do
    serial=$(basename "$cert" .crt)
    if [ -f "data/keys/${serial}.key" ]; then
        vibecert import --cert "$cert" --key "data/keys/${serial}.key"
    else
        vibecert import --cert "$cert"
    fi
done
```

## Database Location

The SQLite database is stored at `data/vibecert.db`. You can query it directly using the `sqlite3` command-line tool:

```bash
# View all certificates
sqlite3 data/vibecert.db "SELECT serial_number, subject, CASE WHEN key_hash IS NULL THEN 'No' ELSE 'Yes' END as has_key FROM certificates;"

# View certificate details
sqlite3 data/vibecert.db "SELECT * FROM certificates WHERE subject LIKE '%Root CA%';"
```

## Security Considerations

- Private keys are encrypted using AES-256-CBC with password-based encryption
- Public key hashes are used to link certificates with their corresponding private keys
- The SQLite database should be backed up regularly and stored securely
- Consider setting appropriate file permissions on the `data/` directory (e.g., `chmod 700 data/`)

## Examples

### Basic Workflow
```bash
# Create a root CA
vibecert create-root --cn "My Root CA"

# View the certificate tree
vibecert tree

# Create an intermediate CA (you'll need the root CA's serial number from the tree output)
vibecert create-intermediate --cn "My Intermediate CA" --ca-serial <root_serial>

# Create a server certificate
vibecert create-leaf --cn "server.example.com" --ca-serial <intermediate_serial> --san-dns "server.example.com,*.server.example.com"

# Export the server certificate and key as PKCS#12 for deployment
vibecert export-pkcs12 --serial <server_serial> --output server.p12 --name "Server Certificate"
```

### Import Existing Certificates
```bash
# Import a certificate chain
vibecert import --cert root-ca.pem --key root-ca.key
vibecert import --cert intermediate-ca.pem --key intermediate-ca.key
vibecert import --cert server.pem --key server.key

# View the imported tree
vibecert tree
```

## Building from Source

```bash
go build -o vibecert .
```

## Dependencies

- Go 1.24.3 or later
- github.com/mattn/go-sqlite3
- golang.org/x/crypto
- software.sslmate.com/src/go-pkcs12

## License

This project follows the same license as the original VibeCert implementation.