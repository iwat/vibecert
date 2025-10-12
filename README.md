# VibeCert - SQLite Certificate Management System

VibeCert is a certificate and private key management system that uses SQLite for storage. It provides a modern approach to certificate lifecycle management with advanced querying capabilities.

## Features

- **SQLite Database Storage**: All certificates and keys are stored in a SQLite database for efficient querying and management
- **Certificate Chain Visualization**: Display certificate dependency trees
- **Import/Export Operations**: Import existing certificates and keys, export in various formats
- **Key Management**: Secure private key storage with password-based encryption
- **PKCS#12 Export**: Export certificates and keys as PKCS#12 files for easy deployment
- **Human-Readable Certificate Export**: Export certificate details similar to `openssl x509 -text`

## Migration from File-Based Storage

If you have existing certificates stored in PEM files, you can import them:

```bash
for cert in `ls *.crt`; do
  go run . certificate import $cert
done

for key in `ls *.key`; do
  go run . key import $key
done
```

## Database Location

The SQLite database is stored in the user's standard configuration directory by default:

- **Linux/Unix**: `$XDG_CONFIG_HOME/vibecert/vibecert.db` or `~/.config/vibecert/vibecert.db`
- **macOS**: `~/Library/Application Support/vibecert/vibecert.db`
- **Windows**: `%APPDATA%/vibecert/vibecert.db`

### Database Path Options

You can override the default database location using:

1. **Command-line flag**: `vibecert --db /path/to/custom.db <command>`
2. **Default location**: Uses OS-specific user config directory

You can query the database directly using the `sqlite3` command-line tool:

```bash
# View all certificates (using default database location)
vibecert --db ~/.config/vibecert/vibecert.db  # Linux example
sqlite3 ~/.config/vibecert/vibecert.db "SELECT * FROM certificate;"

# Quick way to find your database location
vibecert --help  # Shows default database path
```

## Security Considerations

- Private keys are encrypted using AES-256-CBC with password-based encryption
- Public key hashes are used to link certificates with their corresponding private keys
- The SQLite database should be backed up regularly and stored securely
- The default database directory is created with restrictive permissions (700)
- Consider additional file system encryption for sensitive certificate environments
- Delete operations are atomic and check for certificate dependencies before deletion

## Examples

### Basic Workflow
```bash
# Create a root CA (uses default database location)
vibecert certificate create-root --cn "My Root CA"

# View the certificate tree
vibecert certificate tree

# Create an intermediate CA (you'll need the root CA's ID from the tree output)
vibecert certificate create-intermediate --cn "My Intermediate CA" --issuer-id 1

# Create a server certificate
vibecert certificate create-leaf --cn "server.example.com"

# Export the server certificate and key as PKCS#12 for deployment
vibecert export-pkcs12 --serial <server_serial> --output server.p12 --name "Server Certificate"

# Using custom database location
vibecert --db /path/to/project.db tree
```

### Import Existing Certificates
```bash
# Import a certificate chain (to default database)
vibecert certificate import root-ca.pem
vibecert key import root-ca.key
vibecert certificate import intermediate-ca.pem
vibecert key import intermediate-ca.key
vibecert certificate import server.pem
vibecert key import server.key
```

## Building from Source

```bash
go build -o vibecert .
```
