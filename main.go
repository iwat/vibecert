package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh/terminal"
	"software.sslmate.com/src/go-pkcs12"
)

type Certificate struct {
	SerialNumber string
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	PEMData      string
	KeyHash      string
	IsSelfSigned bool
	IsRoot       bool
	IsCA         bool
	X509Cert     *x509.Certificate
	Children     []*Certificate
}

type KeyPair struct {
	PublicKeyHash string
	PEMData       string
}

var db *sql.DB
var dbPath string

func main() {
	// Parse global flags first
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		printUsage()
		os.Exit(0)
	}

	// Check for database flag
	var command string
	var commandArgs []string

	for i, arg := range os.Args[1:] {
		if arg == "--db" && i+2 < len(os.Args) {
			dbPath = os.Args[i+2]
			// Remove --db and its value from args
			commandArgs = append(os.Args[1:i+1], os.Args[i+3:]...)
		} else if strings.HasPrefix(arg, "--db=") {
			dbPath = strings.TrimPrefix(arg, "--db=")
			// Remove --db= from args
			commandArgs = append(os.Args[1:i+1], os.Args[i+2:]...)
		}
	}

	if commandArgs == nil {
		commandArgs = os.Args[1:]
	}

	if len(commandArgs) < 1 {
		printUsage()
		os.Exit(1)
	}

	if dbPath == "" {
		var err error
		dbPath, err = getDatabasePath()
		if err != nil {
			log.Fatalf("Failed to get database path: %v", err)
		}
	}

	if err := initDatabase(dbPath); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	command = commandArgs[0]

	// Update os.Args to use filtered command args for flag parsing
	os.Args = append([]string{os.Args[0]}, commandArgs...)

	switch command {
	case "tree":
		runTreeCommand()
	case "create-root":
		runCreateRootCommand()
	case "create-intermediate":
		runCreateIntermediateCommand()
	case "create-leaf":
		runCreateLeafCommand()
	case "import":
		runImportCommand()
	case "export-cert":
		runExportCertCommand()
	case "export-key":
		runExportKeyCommand()
	case "reencrypt-key":
		runReencryptKeyCommand()
	case "export-pkcs12":
		runExportPKCS12Command()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: vibecert [global-options] <command> [arguments]")
	fmt.Println("")
	fmt.Println("Global options:")
	fmt.Println("  --db <path>      Path to SQLite database file")
	fmt.Println("")
	fmt.Println("Available commands:")
	fmt.Println("  tree             Display certificate dependency tree")
	fmt.Println("  create-root      Generate a new root certificate and key")
	fmt.Println("  create-intermediate Generate an intermediate CA certificate")
	fmt.Println("  create-leaf      Generate an end-entity certificate")
	fmt.Println("  import           Import certificate and optional key")
	fmt.Println("  export-cert      Export certificate with human-readable content")
	fmt.Println("  export-key       Export encrypted private key")
	fmt.Println("  reencrypt-key    Change private key password")
	fmt.Println("  export-pkcs12    Export certificate and key as PKCS#12 file")
	fmt.Println("  help             Show this help message")
	fmt.Println("")
	fmt.Println("Database location:")
	fmt.Printf("  Default: %s\n", getDefaultDatabasePath())
	fmt.Println("  Override with --db flag or VIBECERT_DB environment variable")
	fmt.Println("")
	fmt.Println("For command-specific help, use: vibecert <command> --help")
}

func getDatabasePath() (string, error) {
	// Check if user provided explicit database path via environment variable
	if dbPath := os.Getenv("VIBECERT_DB"); dbPath != "" {
		// Ensure the directory exists
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", fmt.Errorf("failed to create database directory %s: %v", dir, err)
		}
		return dbPath, nil
	}

	return getDefaultDatabasePath(), nil
}

func getDefaultDatabasePath() string {
	// Use standard user config directory
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Fallback to current directory if config dir is not available
		return "./vibecert.db"
	}

	vibecertDir := filepath.Join(configDir, "vibecert")
	if err := os.MkdirAll(vibecertDir, 0700); err != nil {
		// Fallback to current directory if we can't create config dir
		return "./vibecert.db"
	}

	return filepath.Join(vibecertDir, "vibecert.db")
}

func initDatabase(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	// Create certificates table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS certificates (
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
		)
	`)
	if err != nil {
		return err
	}

	// Create keys table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys (
			public_key_hash TEXT PRIMARY KEY,
			pem_data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	return nil
}

func calculatePublicKeyHash(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

func runTreeCommand() {
	certificates, err := loadCertificatesFromDB()
	if err != nil {
		log.Fatalf("Failed to load certificates: %v", err)
	}

	tree := buildCertificateTree(certificates)
	sortCertificates(tree)
	printCertificateTree(tree, 0)
}

func loadCertificatesFromDB() ([]*Certificate, error) {
	rows, err := db.Query(`
		SELECT serial_number, subject, issuer, not_before, not_after,
		       pem_data, key_hash, is_self_signed, is_root, is_ca
		FROM certificates
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*Certificate
	for rows.Next() {
		cert := &Certificate{}
		var keyHash sql.NullString

		err := rows.Scan(&cert.SerialNumber, &cert.Subject, &cert.Issuer,
			&cert.NotBefore, &cert.NotAfter, &cert.PEMData, &keyHash,
			&cert.IsSelfSigned, &cert.IsRoot, &cert.IsCA)
		if err != nil {
			return nil, err
		}

		if keyHash.Valid {
			cert.KeyHash = keyHash.String
		}

		// Parse the X.509 certificate
		block, _ := pem.Decode([]byte(cert.PEMData))
		if block == nil {
			continue
		}
		cert.X509Cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		certificates = append(certificates, cert)
	}

	return certificates, nil
}

func buildCertificateTree(certificates []*Certificate) []*Certificate {
	certMap := make(map[string]*Certificate)
	for _, cert := range certificates {
		certMap[cert.SerialNumber] = cert
	}

	var roots []*Certificate
	hasParent := make(map[string]bool)

	for _, cert := range certificates {
		if cert.IsSelfSigned {
			roots = append(roots, cert)
		} else {
			// Find parent by matching issuer
			parentFound := false
			for _, parent := range certificates {
				if parent.Subject == cert.Issuer {
					parent.Children = append(parent.Children, cert)
					hasParent[cert.SerialNumber] = true
					parentFound = true
					break
				}
			}
			// If no parent found, treat as orphan root
			if !parentFound {
				roots = append(roots, cert)
			}
		}
	}

	return roots
}

func sortCertificates(certificates []*Certificate) {
	sort.Slice(certificates, func(i, j int) bool {
		return certificates[i].Subject < certificates[j].Subject
	})

	for _, cert := range certificates {
		sortCertificates(cert.Children)
	}
}

func printCertificateTree(certificates []*Certificate, indent int) {
	indentStr := strings.Repeat("  ", indent)

	for _, cert := range certificates {
		marker := "├─"
		if indent == 0 {
			marker = "└─"
		}

		keyStatus := "No Key"
		if cert.KeyHash != "" {
			keyStatus = "Has Key"
		}

		fmt.Printf("%s%s %s (Serial: %s) [%s]\n",
			indentStr, marker, cert.Subject, cert.SerialNumber, keyStatus)

		if len(cert.Children) > 0 {
			printCertificateTree(cert.Children, indent+1)
		}
	}
}

func runImportCommand() {
	fs := flag.NewFlagSet("import", flag.ExitOnError)

	var (
		certFile = fs.String("cert", "", "Certificate file path (required)")
		keyFile  = fs.String("key", "", "Private key file path (optional)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert import [flags]")
		fmt.Println("")
		fmt.Println("Import a certificate and optionally its private key.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *certFile == "" {
		fmt.Println("Error: cert file is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load certificate
	certData, err := os.ReadFile(*certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}

	cert, err := parseCertificateFromPEM(string(certData))
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// Calculate key hash
	keyHash := calculatePublicKeyHash(cert.X509Cert)

	// Import key if provided
	if *keyFile != "" {
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			log.Fatalf("Failed to read key file: %v", err)
		}

		// Store the key
		_, err = db.Exec(`
			INSERT OR REPLACE INTO keys (public_key_hash, pem_data)
			VALUES (?, ?)
		`, keyHash, string(keyData))
		if err != nil {
			log.Fatalf("Failed to store key: %v", err)
		}

		cert.KeyHash = keyHash
	}

	// Store certificate
	_, err = db.Exec(`
		INSERT OR REPLACE INTO certificates
		(serial_number, subject, issuer, not_before, not_after,
		 pem_data, key_hash, is_self_signed, is_root, is_ca)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.SerialNumber, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter,
		cert.PEMData, cert.KeyHash, cert.IsSelfSigned, cert.IsRoot, cert.IsCA)
	if err != nil {
		log.Fatalf("Failed to store certificate: %v", err)
	}

	fmt.Printf("Certificate imported successfully:\n")
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	if cert.KeyHash != "" {
		fmt.Printf("  Private key: imported\n")
	} else {
		fmt.Printf("  Private key: not provided\n")
	}
}

func parseCertificateFromPEM(pemData string) (*Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM data")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	cert := &Certificate{
		SerialNumber: fmt.Sprintf("%032x", x509Cert.SerialNumber),
		Subject:      x509Cert.Subject.String(),
		Issuer:       x509Cert.Issuer.String(),
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		PEMData:      pemData,
		IsSelfSigned: x509Cert.Subject.String() == x509Cert.Issuer.String(),
		IsRoot:       x509Cert.IsCA && x509Cert.Subject.String() == x509Cert.Issuer.String(),
		IsCA:         x509Cert.IsCA,
		X509Cert:     x509Cert,
	}

	return cert, nil
}

func runExportCertCommand() {
	fs := flag.NewFlagSet("export-cert", flag.ExitOnError)

	var (
		serial     = fs.String("serial", "", "Certificate serial number (required)")
		outputFile = fs.String("output", "", "Output file path (default: {serial}.txt)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert export-cert [flags]")
		fmt.Println("")
		fmt.Println("Export certificate with human-readable content similar to 'openssl x509 -text'.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *serial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load certificate from database
	var pemData string
	err := db.QueryRow("SELECT pem_data FROM certificates WHERE serial_number = ?", *serial).Scan(&pemData)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatalf("Certificate with serial %s not found", *serial)
		}
		log.Fatalf("Failed to load certificate: %v", err)
	}

	cert, err := parseCertificateFromPEM(pemData)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// Generate human-readable output
	output := generateCertificateText(cert)

	// Determine output file
	outputPath := *outputFile
	if outputPath == "" {
		outputPath = fmt.Sprintf("%s.txt", *serial)
	}

	// Write to file
	err = os.WriteFile(outputPath, []byte(output), 0644)
	if err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}

	fmt.Printf("Certificate exported to: %s\n", outputPath)
}

func generateCertificateText(cert *Certificate) string {
	var builder strings.Builder

	builder.WriteString("Certificate:\n")
	builder.WriteString("    Data:\n")
	builder.WriteString(fmt.Sprintf("        Version: %d\n", cert.X509Cert.Version))
	builder.WriteString(fmt.Sprintf("        Serial Number: %s\n", cert.SerialNumber))
	builder.WriteString("    Signature Algorithm: " + cert.X509Cert.SignatureAlgorithm.String() + "\n")
	builder.WriteString("        Issuer: " + cert.Issuer + "\n")
	builder.WriteString("        Validity:\n")
	builder.WriteString(fmt.Sprintf("            Not Before: %s\n", cert.NotBefore.Format("Jan 2 15:04:05 2006 MST")))
	builder.WriteString(fmt.Sprintf("            Not After:  %s\n", cert.NotAfter.Format("Jan 2 15:04:05 2006 MST")))
	builder.WriteString("        Subject: " + cert.Subject + "\n")

	if cert.IsCA {
		builder.WriteString("        CA: TRUE\n")
	}

	if len(cert.X509Cert.DNSNames) > 0 {
		builder.WriteString("        Subject Alternative Name:\n")
		for _, dns := range cert.X509Cert.DNSNames {
			builder.WriteString(fmt.Sprintf("            DNS:%s\n", dns))
		}
	}

	builder.WriteString("\n" + cert.PEMData)

	return builder.String()
}

func runExportKeyCommand() {
	fs := flag.NewFlagSet("export-key", flag.ExitOnError)

	var (
		serial     = fs.String("serial", "", "Certificate serial number (required)")
		outputFile = fs.String("output", "", "Output key file path (default: {serial}.key)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert export-key [flags]")
		fmt.Println("")
		fmt.Println("Export the encrypted private key for a certificate.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *serial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load certificate to get key hash
	var keyHash sql.NullString
	err := db.QueryRow("SELECT key_hash FROM certificates WHERE serial_number = ?", *serial).Scan(&keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatalf("Certificate with serial %s not found", *serial)
		}
		log.Fatalf("Failed to load certificate: %v", err)
	}

	if !keyHash.Valid {
		log.Fatalf("No private key associated with certificate %s", *serial)
	}

	// Load key data
	var keyData string
	err = db.QueryRow("SELECT pem_data FROM keys WHERE public_key_hash = ?", keyHash.String).Scan(&keyData)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// Determine output file
	outputPath := *outputFile
	if outputPath == "" {
		outputPath = fmt.Sprintf("%s.key", *serial)
	}

	// Write to file
	err = os.WriteFile(outputPath, []byte(keyData), 0600)
	if err != nil {
		log.Fatalf("Failed to write key file: %v", err)
	}

	fmt.Printf("Private key exported to: %s\n", outputPath)
}

func runReencryptKeyCommand() {
	fs := flag.NewFlagSet("reencrypt-key", flag.ExitOnError)

	var (
		serial = fs.String("serial", "", "Certificate serial number (required)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert reencrypt-key [flags]")
		fmt.Println("")
		fmt.Println("Change the password of a private key.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *serial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load certificate to get key hash
	var keyHash sql.NullString
	err := db.QueryRow("SELECT key_hash FROM certificates WHERE serial_number = ?", *serial).Scan(&keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Fatalf("Certificate with serial %s not found", *serial)
		}
		log.Fatalf("Failed to load certificate: %v", err)
	}

	if !keyHash.Valid {
		log.Fatalf("No private key associated with certificate %s", *serial)
	}

	// Load key data
	var keyData string
	err = db.QueryRow("SELECT pem_data FROM keys WHERE public_key_hash = ?", keyHash.String).Scan(&keyData)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// Get current password
	fmt.Print("Enter current password: ")
	currentPasswordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read current password: %v", err)
	}
	fmt.Println()

	// Decrypt the key to verify current password
	privateKey, err := loadPrivateKeyFromPEM(keyData, string(currentPasswordBytes))
	if err != nil {
		log.Fatalf("Failed to decrypt private key (wrong password?): %v", err)
	}

	// Get new password
	fmt.Print("Enter new password: ")
	newPasswordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read new password: %v", err)
	}
	fmt.Println()

	fmt.Print("Confirm new password: ")
	confirmPasswordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password confirmation: %v", err)
	}
	fmt.Println()

	newPassword := string(newPasswordBytes)
	if newPassword != string(confirmPasswordBytes) {
		log.Fatalf("Passwords do not match")
	}

	// Re-encrypt with new password
	newKeyData, err := encryptPrivateKey(privateKey, newPassword)
	if err != nil {
		log.Fatalf("Failed to encrypt private key with new password: %v", err)
	}

	// Update in database
	_, err = db.Exec("UPDATE keys SET pem_data = ? WHERE public_key_hash = ?", newKeyData, keyHash.String)
	if err != nil {
		log.Fatalf("Failed to update private key: %v", err)
	}

	fmt.Printf("Private key password changed successfully for certificate %s\n", *serial)
}

func loadPrivateKeyFromPEM(pemData, password string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var keyBytes []byte
	var err error

	if x509.IsEncryptedPEMBlock(block) {
		keyBytes, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	} else {
		keyBytes = block.Bytes
	}

	// Try parsing as different key types
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

func encryptPrivateKey(privateKey interface{}, password string) (string, error) {
	var keyBytes []byte
	var err error

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(key)
	default:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
	}

	if err != nil {
		return "", err
	}

	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", keyBytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(encryptedBlock)), nil
}

func runExportPKCS12Command() {
	fs := flag.NewFlagSet("export-pkcs12", flag.ExitOnError)

	var (
		certSerial     = fs.String("serial", "", "Serial number of certificate to export (required)")
		outputFile     = fs.String("output", "", "Output PKCS#12 file path (default: {serial}.p12)")
		friendlyName   = fs.String("name", "", "Friendly name for the certificate (default: certificate CN)")
		includeCACerts = fs.Bool("include-ca", true, "Include CA certificates in the chain")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert export-pkcs12 [flags]")
		fmt.Println("")
		fmt.Println("Export a certificate and its private key as a PKCS#12 file.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *certSerial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load certificate and key
	cert, privateKey, err := loadCertificateAndKey(*certSerial)
	if err != nil {
		log.Fatalf("Failed to load certificate and key: %v", err)
	}

	// Prompt for PKCS#12 export password
	fmt.Print("Enter password for PKCS#12 file: ")
	p12PasswordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read PKCS#12 password: %v", err)
	}
	fmt.Println()
	p12Password := string(p12PasswordBytes)

	if len(p12Password) == 0 {
		fmt.Println("Error: PKCS#12 password cannot be empty")
		os.Exit(1)
	}

	// Set friendly name
	name := *friendlyName
	if name == "" {
		name = cert.X509Cert.Subject.CommonName
		if name == "" {
			name = fmt.Sprintf("Certificate %s", *certSerial)
		}
	}

	// Collect CA certificates if requested
	var caCerts []*x509.Certificate
	if *includeCACerts {
		caCerts, err = collectCACertificatesFromDB(cert)
		if err != nil {
			fmt.Printf("Warning: Failed to collect CA certificates: %v\n", err)
		}
	}

	// Create PKCS#12 data
	pfxData, err := pkcs12.Modern.Encode(privateKey, cert.X509Cert, caCerts, p12Password)
	if err != nil {
		log.Fatalf("Failed to create PKCS#12 data: %v", err)
	}

	// Determine output file
	output := *outputFile
	if output == "" {
		output = fmt.Sprintf("%s.p12", *certSerial)
	}

	// Save PKCS#12 file
	if err := os.WriteFile(output, pfxData, 0600); err != nil {
		log.Fatalf("Failed to save PKCS#12 file: %v", err)
	}

	fmt.Printf("PKCS#12 file exported successfully:\n")
	fmt.Printf("  File: %s\n", output)
	fmt.Printf("  Certificate: %s\n", cert.X509Cert.Subject.CommonName)
	fmt.Printf("  Friendly name: %s\n", name)
	if len(caCerts) > 0 {
		fmt.Printf("  CA certificates included: %d\n", len(caCerts))
	}
}

func loadCertificateAndKey(serial string) (*Certificate, interface{}, error) {
	// Load certificate
	var pemData string
	var keyHash sql.NullString
	err := db.QueryRow(`
		SELECT pem_data, key_hash
		FROM certificates
		WHERE serial_number = ?
	`, serial).Scan(&pemData, &keyHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, fmt.Errorf("certificate with serial %s not found", serial)
		}
		return nil, nil, err
	}

	if !keyHash.Valid {
		return nil, nil, fmt.Errorf("no private key associated with certificate %s", serial)
	}

	cert, err := parseCertificateFromPEM(pemData)
	if err != nil {
		return nil, nil, err
	}

	// Load private key
	var keyData string
	err = db.QueryRow("SELECT pem_data FROM keys WHERE public_key_hash = ?", keyHash.String).Scan(&keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %v", err)
	}

	// Prompt for key password
	fmt.Print("Enter password for private key: ")
	keyPasswordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key password: %v", err)
	}
	fmt.Println()

	privateKey, err := loadPrivateKeyFromPEM(keyData, string(keyPasswordBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	return cert, privateKey, nil
}

func collectCACertificatesFromDB(cert *Certificate) ([]*x509.Certificate, error) {
	var caCerts []*x509.Certificate

	// Find parent certificates
	currentIssuer := cert.Issuer
	for currentIssuer != cert.Subject { // Stop when we reach a self-signed cert
		var pemData string
		var subject string
		err := db.QueryRow(`
			SELECT pem_data, subject
			FROM certificates
			WHERE subject = ? AND is_ca = 1
		`, currentIssuer).Scan(&pemData, &subject)

		if err != nil {
			if err == sql.ErrNoRows {
				break // No more parents found
			}
			return nil, err
		}

		parentCert, err := parseCertificateFromPEM(pemData)
		if err != nil {
			continue
		}

		caCerts = append(caCerts, parentCert.X509Cert)

		if parentCert.IsSelfSigned {
			break
		}
		currentIssuer = parentCert.Issuer
	}

	return caCerts, nil
}

// Legacy functions for create commands - simplified versions that store in DB
func runCreateRootCommand() {
	fs := flag.NewFlagSet("create-root", flag.ExitOnError)

	var (
		commonName = fs.String("cn", "", "Common Name (required)")
		keySize    = fs.Int("key-size", 4096, "RSA key size")
		validDays  = fs.Int("valid-days", 3650, "Certificate validity in days")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert create-root [flags]")
		fmt.Println("")
		fmt.Println("Generate a new root CA certificate and private key.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *commonName == "" {
		fmt.Println("Error: common name (-cn) is required")
		fs.Usage()
		os.Exit(1)
	}

	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Prompt for password
	fmt.Print("Enter password to encrypt private key: ")
	passwordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	if len(password) == 0 {
		fmt.Println("Error: password cannot be empty")
		os.Exit(1)
	}

	// Generate certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: *commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, *validDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate (self-signed)
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Convert to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Parse certificate to get details
	cert, err := parseCertificateFromPEM(string(certPEM))
	if err != nil {
		log.Fatalf("Failed to parse generated certificate: %v", err)
	}

	// Calculate key hash
	keyHash := calculatePublicKeyHash(cert.X509Cert)

	// Encrypt and store private key
	keyPEM, err := encryptPrivateKey(privateKey, password)
	if err != nil {
		log.Fatalf("Failed to encrypt private key: %v", err)
	}

	// Store key in database
	_, err = db.Exec(`
		INSERT INTO keys (public_key_hash, pem_data)
		VALUES (?, ?)
	`, keyHash, keyPEM)
	if err != nil {
		log.Fatalf("Failed to store private key: %v", err)
	}

	// Store certificate in database
	cert.KeyHash = keyHash
	_, err = db.Exec(`
		INSERT INTO certificates
		(serial_number, subject, issuer, not_before, not_after,
		 pem_data, key_hash, is_self_signed, is_root, is_ca)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.SerialNumber, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter,
		cert.PEMData, cert.KeyHash, cert.IsSelfSigned, cert.IsRoot, cert.IsCA)
	if err != nil {
		log.Fatalf("Failed to store certificate: %v", err)
	}

	fmt.Printf("Root CA certificate generated successfully:\n")
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Valid for: %d days\n", *validDays)
}

func runCreateIntermediateCommand() {
	fs := flag.NewFlagSet("create-intermediate", flag.ExitOnError)

	var (
		commonName = fs.String("cn", "", "Common Name (required)")
		caSerial   = fs.String("ca-serial", "", "Parent CA serial number (required)")
		keySize    = fs.Int("key-size", 4096, "RSA key size")
		validDays  = fs.Int("valid-days", 1825, "Certificate validity in days")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert create-intermediate [flags]")
		fmt.Println("")
		fmt.Println("Generate an intermediate CA certificate signed by an existing CA.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *commonName == "" || *caSerial == "" {
		fmt.Println("Error: common name (-cn) and ca-serial are required")
		fs.Usage()
		os.Exit(1)
	}

	// Load parent CA certificate and key
	parentCert, parentKey, err := loadCertificateAndKey(*caSerial)
	if err != nil {
		log.Fatalf("Failed to load parent CA: %v", err)
	}

	if !parentCert.IsCA {
		log.Fatalf("Parent certificate is not a CA")
	}

	// Generate new key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Prompt for password for new key
	fmt.Print("Enter password to encrypt new private key: ")
	passwordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	if len(password) == 0 {
		fmt.Println("Error: password cannot be empty")
		os.Exit(1)
	}

	// Generate serial number
	serialBytes := make([]byte, 16)
	rand.Read(serialBytes)
	serial := new(big.Int).SetBytes(serialBytes)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: *commonName,
		},
		Issuer:                parentCert.X509Cert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, *validDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert.X509Cert, &privateKey.PublicKey, parentKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Convert to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Parse certificate to get details
	cert, err := parseCertificateFromPEM(string(certPEM))
	if err != nil {
		log.Fatalf("Failed to parse generated certificate: %v", err)
	}

	// Calculate key hash and store
	keyHash := calculatePublicKeyHash(cert.X509Cert)
	keyPEM, err := encryptPrivateKey(privateKey, password)
	if err != nil {
		log.Fatalf("Failed to encrypt private key: %v", err)
	}

	// Store key in database
	_, err = db.Exec(`
		INSERT INTO keys (public_key_hash, pem_data)
		VALUES (?, ?)
	`, keyHash, keyPEM)
	if err != nil {
		log.Fatalf("Failed to store private key: %v", err)
	}

	// Store certificate in database
	cert.KeyHash = keyHash
	_, err = db.Exec(`
		INSERT INTO certificates
		(serial_number, subject, issuer, not_before, not_after,
		 pem_data, key_hash, is_self_signed, is_root, is_ca)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.SerialNumber, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter,
		cert.PEMData, cert.KeyHash, cert.IsSelfSigned, cert.IsRoot, cert.IsCA)
	if err != nil {
		log.Fatalf("Failed to store certificate: %v", err)
	}

	fmt.Printf("Intermediate CA certificate generated successfully:\n")
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Parent: %s\n", parentCert.SerialNumber)
	fmt.Printf("  Valid for: %d days\n", *validDays)
}

func runCreateLeafCommand() {
	fs := flag.NewFlagSet("create-leaf", flag.ExitOnError)

	var (
		commonName = fs.String("cn", "", "Common Name (required)")
		caSerial   = fs.String("ca-serial", "", "Parent CA serial number (required)")
		keySize    = fs.Int("key-size", 4096, "RSA key size")
		validDays  = fs.Int("valid-days", 365, "Certificate validity in days")
		sanDNS     = fs.String("san-dns", "", "DNS names for SAN (comma-separated)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert create-leaf [flags]")
		fmt.Println("")
		fmt.Println("Generate an end-entity certificate signed by an existing CA.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(os.Args[2:])

	if *commonName == "" || *caSerial == "" {
		fmt.Println("Error: common name (-cn) and ca-serial are required")
		fs.Usage()
		os.Exit(1)
	}

	// Load parent CA certificate and key
	parentCert, parentKey, err := loadCertificateAndKey(*caSerial)
	if err != nil {
		log.Fatalf("Failed to load parent CA: %v", err)
	}

	if !parentCert.IsCA {
		log.Fatalf("Parent certificate is not a CA")
	}

	// Generate new key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, *keySize)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Prompt for password for new key
	fmt.Print("Enter password to encrypt new private key: ")
	passwordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	if len(password) == 0 {
		fmt.Println("Error: password cannot be empty")
		os.Exit(1)
	}

	// Generate serial number
	serialBytes := make([]byte, 16)
	rand.Read(serialBytes)
	serial := new(big.Int).SetBytes(serialBytes)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: *commonName,
		},
		Issuer:                parentCert.X509Cert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, *validDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add SAN DNS names if provided
	if *sanDNS != "" {
		dnsNames := strings.Split(*sanDNS, ",")
		for i, name := range dnsNames {
			dnsNames[i] = strings.TrimSpace(name)
		}
		template.DNSNames = dnsNames
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert.X509Cert, &privateKey.PublicKey, parentKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Convert to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Parse certificate to get details
	cert, err := parseCertificateFromPEM(string(certPEM))
	if err != nil {
		log.Fatalf("Failed to parse generated certificate: %v", err)
	}

	// Calculate key hash and store
	keyHash := calculatePublicKeyHash(cert.X509Cert)
	keyPEM, err := encryptPrivateKey(privateKey, password)
	if err != nil {
		log.Fatalf("Failed to encrypt private key: %v", err)
	}

	// Store key in database
	_, err = db.Exec(`
		INSERT INTO keys (public_key_hash, pem_data)
		VALUES (?, ?)
	`, keyHash, keyPEM)
	if err != nil {
		log.Fatalf("Failed to store private key: %v", err)
	}

	// Store certificate in database
	cert.KeyHash = keyHash
	_, err = db.Exec(`
		INSERT INTO certificates
		(serial_number, subject, issuer, not_before, not_after,
		 pem_data, key_hash, is_self_signed, is_root, is_ca)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.SerialNumber, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter,
		cert.PEMData, cert.KeyHash, cert.IsSelfSigned, cert.IsRoot, cert.IsCA)
	if err != nil {
		log.Fatalf("Failed to store certificate: %v", err)
	}

	fmt.Printf("End-entity certificate generated successfully:\n")
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Parent: %s\n", parentCert.SerialNumber)
	fmt.Printf("  Valid for: %d days\n", *validDays)
	if len(template.DNSNames) > 0 {
		fmt.Printf("  DNS SANs: %s\n", strings.Join(template.DNSNames, ", "))
	}
}
