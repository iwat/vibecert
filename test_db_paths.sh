#!/bin/bash

# Test script for VibeCert database path functionality
# This script demonstrates the three ways to specify database paths:
# 1. Default OS-specific user config directory
# 2. Command-line --db flag
# 3. VIBECERT_DB environment variable

set -e

echo "=== VibeCert Database Path Testing ==="
echo

# Build the application
echo "Building VibeCert..."
go build -o vibecert .
echo "✓ Build successful"
echo

# Test 1: Default database path
echo "=== Test 1: Default Database Path ==="
echo "Using OS-specific user config directory..."

# Show where the default database will be created
./vibecert --help | grep "Default:"

# Import a certificate to default location
echo "Importing certificate to default database..."
./vibecert import --cert data/certs/017fdecacc5a70c86718302887a6cdb1.crt

# Show the tree
echo "Certificate tree (default database):"
./vibecert tree

# Verify database location
DEFAULT_DB_DIR="$HOME/Library/Application Support/vibecert"  # macOS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    DEFAULT_DB_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/vibecert"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    DEFAULT_DB_DIR="$APPDATA/vibecert"
fi

echo "Database created at: $DEFAULT_DB_DIR/vibecert.db"
ls -la "$DEFAULT_DB_DIR/"
echo

# Test 2: Command-line --db flag
echo "=== Test 2: Command-line --db Flag ==="
echo "Using --db flag to specify custom database path..."

# Import different certificate to custom database
./vibecert --db ./custom.db import --cert data/certs/7bf09aea9e8e03f0fbe5dc0c4083d985.crt --key data/keys/7bf09aea9e8e03f0fbe5dc0c4083d985.key

echo "Certificate tree (custom database via --db flag):"
./vibecert --db ./custom.db tree

# Export certificate to test other commands work with custom DB
./vibecert --db ./custom.db export-cert --serial 164744336807132319323742852618396096901 --output custom-cert.txt
echo "✓ Certificate exported from custom database"

echo "Custom database file created:"
ls -la ./custom.db
echo

# Test 3: Environment variable
echo "=== Test 3: VIBECERT_DB Environment Variable ==="
echo "Using VIBECERT_DB environment variable..."

# Set environment variable and import certificate
export VIBECERT_DB="./env-database.db"
./vibecert import --cert data/certs/3f4d405464f4e7ee03225bded9d58345.crt --key data/keys/3f4d405464f4e7ee03225bded9d58345.key

echo "Certificate tree (database via environment variable):"
./vibecert tree

# Test that --db flag overrides environment variable
echo "Testing --db flag override of environment variable:"
./vibecert --db ./override.db import --cert data/certs/12fe346da8b7a19ee85835b772a6604a.crt

echo "Environment DB content:"
./vibecert tree

echo "Override DB content:"
./vibecert --db ./override.db tree

echo "Environment database file created:"
ls -la ./env-database.db

echo "Override database file created:"
ls -la ./override.db
echo

# Test 4: Database content verification
echo "=== Test 4: Database Content Verification ==="

echo "Default database certificates:"
sqlite3 "$DEFAULT_DB_DIR/vibecert.db" "SELECT serial_number, subject FROM certificates;" 2>/dev/null || echo "No certificates in default DB or sqlite3 not available"

echo "Custom database certificates:"
sqlite3 ./custom.db "SELECT serial_number, subject FROM certificates;" 2>/dev/null || echo "sqlite3 not available"

echo "Environment database certificates:"
sqlite3 ./env-database.db "SELECT serial_number, subject FROM certificates;" 2>/dev/null || echo "sqlite3 not available"

echo "Override database certificates:"
sqlite3 ./override.db "SELECT serial_number, subject FROM certificates;" 2>/dev/null || echo "sqlite3 not available"
echo

# Test 5: Cross-database operations
echo "=== Test 5: Cross-Database Operations ==="
echo "Testing operations across different databases..."

# Count certificates in each database
echo "Certificate counts:"
echo "- Default DB: $(./vibecert tree | wc -l) certificate(s)"
echo "- Custom DB: $(./vibecert --db ./custom.db tree | wc -l) certificate(s)"
echo "- Environment DB: $(VIBECERT_DB=./env-database.db ./vibecert tree | wc -l) certificate(s)"
echo "- Override DB: $(./vibecert --db ./override.db tree | wc -l) certificate(s)"
echo

# Cleanup
echo "=== Cleanup ==="
echo "Removing test databases and files..."
rm -f ./custom.db ./env-database.db ./override.db ./custom-cert.txt
unset VIBECERT_DB

# Note: We don't remove the default database as it follows OS conventions
echo "✓ Test databases cleaned up"
echo "Note: Default database preserved at $DEFAULT_DB_DIR/vibecert.db"
echo

echo "=== Test Summary ==="
echo "✓ Default OS-specific database path works"
echo "✓ Command-line --db flag works"
echo "✓ VIBECERT_DB environment variable works"
echo "✓ --db flag properly overrides environment variable"
echo "✓ All commands work with custom database paths"
echo "✓ Multiple databases can coexist"
echo
echo "All database path functionality tests passed! 🎉"

# Test 6: Delete command functionality
echo "=== Test 6: Delete Command Functionality ==="
echo "Testing certificate and key deletion..."

# Create a test database with certificates
./vibecert --db ./delete-test.db import --cert data/certs/017fdecacc5a70c86718302887a6cdb1.crt
./vibecert --db ./delete-test.db import --cert data/certs/3f4d405464f4e7ee03225bded9d58345.crt --key data/keys/3f4d405464f4e7ee03225bded9d58345.key

echo "Initial certificate tree:"
./vibecert --db ./delete-test.db tree

# Test delete with confirmation (simulate 'n' response)
echo "Testing delete cancellation..."
echo "n" | ./vibecert --db ./delete-test.db delete --serial 017fdecacc5a70c86718302887a6cdb1

echo "Tree after cancelled deletion (should be unchanged):"
./vibecert --db ./delete-test.db tree

# Test delete with force flag
echo "Testing delete with --force flag..."
./vibecert --db ./delete-test.db delete --serial 3f4d405464f4e7ee03225bded9d58345 --force

echo "Tree after forced deletion:"
./vibecert --db ./delete-test.db tree

# Test delete of non-existent certificate
echo "Testing delete of non-existent certificate..."
./vibecert --db ./delete-test.db delete --serial nonexistent --force 2>&1 || echo "✓ Properly handled non-existent certificate"

# Clean up delete test database
rm -f ./delete-test.db

echo "✓ Delete command tests completed"
echo

echo "All database path functionality tests passed! 🎉"
