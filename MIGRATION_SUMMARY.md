# VibeCert SQLite Migration Summary

## Overview

Successfully migrated VibeCert from file-based storage to SQLite database storage with enhanced functionality and improved certificate management capabilities.

## Migration Accomplishments

### ✅ Database Schema Implementation
- **Certificates Table**: Stores certificate metadata with serial number as primary key
  - Issuer, Subject, validity period stored in dedicated fields for efficient querying
  - Complete X.509 PEM data stored as text blob
  - Certificate type flags (is_ca, is_root, is_self_signed)
  - Links to private keys via SHA256 public key hash

- **Keys Table**: Stores encrypted private keys
  - SHA256 hash of public key as primary key
  - Encrypted PEM data stored as text blob
  - Secure linkage to certificates

### ✅ New Commands Implemented

#### Import Commands
- `vibecert import --cert <file> [--key <file>]`
  - Import certificates with or without private keys
  - Automatic public key hash calculation and storage
  - Graceful handling of certificates without keys

#### Export Commands
- `vibecert export-cert --serial <serial> [--output <file>]`
  - Human-readable certificate export (similar to `openssl x509 -text`)
  - Shows certificate details, validity, extensions, and PEM data

- `vibecert export-key --serial <serial> [--output <file>]`
  - Export encrypted private keys
  - Maintains original encryption and format

- `vibecert reencrypt-key --serial <serial>`
  - Change private key passwords interactively
  - Prompts for current password, new password, and confirmation
  - Updates database with re-encrypted key

#### Enhanced PKCS#12 Export
- `vibecert export-pkcs12 --serial <serial> [--output <file>] [--name <name>] [--include-ca]`
  - Reworked to use database storage
  - Automatic CA certificate chain collection from database
  - Compatible with original functionality

### ✅ Preserved Legacy Commands
- `vibecert create-root` - Creates root CA certificates (now stores in DB)
- `vibecert create-intermediate` - Creates intermediate CA certificates
- `vibecert create-leaf` - Creates end-entity certificates
- `vibecert tree` - Enhanced certificate tree visualization

## Technical Implementation Details

### Database Design
- **Location**: User config directory (OS-specific) or custom path
- **Engine**: SQLite 3 with go-sqlite3 driver
- **Security**: Private keys remain encrypted with user passwords
- **Relationships**: Certificates linked to keys via SHA256 public key hash
- **Path Options**: Command-line flag, environment variable, or OS default

### Key Features Added
1. **Certificate Serial Number as Primary Key**: Enables direct certificate lookup
2. **Structured Metadata Storage**: Issuer, subject, validity periods in queryable fields
3. **Public Key Hash Linking**: Secure association between certificates and private keys
4. **Enhanced Tree Visualization**: Shows key availability status
5. **Flexible Import/Export**: Support for various certificate formats and sources
6. **Smart Database Location**: Uses OS-specific user config directories by default
7. **Database Path Flexibility**: Support for custom database locations via CLI or environment

### Security Considerations
- Private keys remain encrypted with AES-256-CBC
- Public key hashes provide secure certificate-to-key mapping
- Database stores encrypted key material only
- No plaintext private key data in database

## Migration Benefits

### Improved Query Capabilities
- Direct SQL queries on certificate metadata
- Efficient filtering by issuer, subject, validity period
- Fast certificate lookups by serial number

### Enhanced Management
- Import existing certificate infrastructure
- Export certificates in multiple formats
- Password management for private keys
- Comprehensive certificate chain handling

### Maintained Compatibility
- All original certificate creation workflows preserved
- PKCS#12 export functionality maintained
- Tree visualization enhanced but familiar

## Database Schema Reference

```sql
-- Certificates table
CREATE TABLE certificates (
    serial_number TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,
    pem_data TEXT NOT NULL,
    key_hash TEXT,
    is_self_signed BOOLEAN NOT NULL,
    is_root BOOLEAN NOT NULL,
    is_ca BOOLEAN NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Keys table  
CREATE TABLE keys (
    public_key_hash TEXT PRIMARY KEY,
    pem_data TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Testing Results

### ✅ Functional Tests Passed
- Database initialization and schema creation
- Certificate import (with and without keys)
- Certificate tree visualization with proper hierarchy
- Certificate export with human-readable format
- Private key export functionality
- PKCS#12 export with CA chain collection

### ✅ Data Integrity Verified
- Proper NULL handling for certificates without keys
- Correct parent-child relationships in certificate trees
- Accurate certificate metadata extraction and storage
- Secure key-certificate associations via public key hashes

## Migration Process for Existing Installations

For users with existing file-based certificates:

```bash
# Import all existing certificates to default database location
for cert in data/certs/*.crt; do
    serial=$(basename "$cert" .crt)
    if [ -f "data/keys/${serial}.key" ]; then
        vibecert import --cert "$cert" --key "data/keys/${serial}.key"
    else
        vibecert import --cert "$cert"
    fi
done

# Or import to a specific database location to preserve old data
vibecert --db ./legacy-certs.db import --cert data/certs/*.crt
```

## Database Location Improvements

The new system uses OS-appropriate configuration directories:
- **Linux/Unix**: `~/.config/vibecert/vibecert.db`
- **macOS**: `~/Library/Application Support/vibecert/vibecert.db`
- **Windows**: `%APPDATA%/vibecert/vibecert.db`

### Path Override Options
- **CLI Flag**: `vibecert --db /path/to/database.db <command>`
- **Environment**: `export VIBECERT_DB=/path/to/database.db`
- **Default**: OS-specific user config directory with secure permissions (700)

## Dependencies Added

- `github.com/mattn/go-sqlite3 v1.14.22` - SQLite database driver

## Future Enhancements Enabled

The new SQLite-based architecture enables:
- Advanced certificate filtering and search
- Certificate expiration monitoring
- Automated certificate renewal workflows  
- Certificate lifecycle management
- Integration with external PKI systems
- Certificate validation and trust chain verification

## Database Path System Implementation

### ✅ OS-Specific Configuration Directory Support
- **macOS**: `~/Library/Application Support/vibecert/vibecert.db`
- **Linux**: `~/.config/vibecert/vibecert.db` (or `$XDG_CONFIG_HOME/vibecert/vibecert.db`)
- **Windows**: `%APPDATA%/vibecert/vibecert.db`
- **Secure Permissions**: Directory created with 700 permissions for enhanced security

### ✅ Flexible Database Path Options
1. **Default Behavior**: Uses OS-appropriate user configuration directory
2. **Command-Line Override**: `vibecert --db /path/to/database.db <command>`
3. **Environment Variable**: `export VIBECERT_DB=/path/to/database.db`
4. **Priority Order**: CLI flag > Environment variable > OS default

### ✅ Enhanced User Experience
- **Automatic Directory Creation**: Creates necessary parent directories automatically
- **Fallback Mechanism**: Falls back to current directory if config dir unavailable
- **Path Display**: Help command shows current default database location
- **Multi-Database Support**: Easy switching between different certificate databases

## Complete Migration Verification

### ✅ Comprehensive Testing Completed
All functionality tested across different database path scenarios:
- Default OS-specific paths working correctly
- Command-line --db flag functioning properly
- Environment variable VIBECERT_DB working as expected
- CLI flag properly overrides environment variable
- All commands (import, export-cert, export-key, export-pkcs12, tree) work with custom paths
- Multiple databases can coexist without interference
- Cross-database operations verified
- Database content isolation confirmed

## Summary

The migration successfully modernizes VibeCert with a robust SQLite database backend while maintaining full compatibility with existing workflows. The new database path system follows OS conventions and provides flexible deployment options. The enhanced import/export capabilities significantly improve certificate management flexibility, and the SQLite foundation enables future advanced PKI management features.

### Migration Benefits Achieved
- **Professional Standards**: Follows OS-specific configuration directory conventions
- **Deployment Flexibility**: Support for project-specific, user-specific, or system-wide databases
- **Security Enhanced**: Proper file permissions and secure default locations
- **Developer Friendly**: Easy switching between development, testing, and production databases
- **Backward Compatible**: Existing certificate creation workflows preserved
- **Future Ready**: Solid foundation for advanced PKI management features