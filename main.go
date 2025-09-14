package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/term"
	"software.sslmate.com/src/go-pkcs12"
)

// CLI wraps the certificate manager with command-line interface
type CLI struct {
	cm     *CertificateManager
	dbPath string
}

// DatabaseWrapper wraps sql.DB to implement DatabaseInterface
type DatabaseWrapper struct {
	*sql.DB
}

func (dw *DatabaseWrapper) Begin() (*sql.Tx, error) {
	return dw.DB.Begin()
}

func (dw *DatabaseWrapper) Close() error {
	return dw.DB.Close()
}

// OSFileWriter implements FileWriter using os.WriteFile
type OSFileWriter struct{}

func (w *OSFileWriter) WriteFile(filename string, data []byte, perm int) error {
	return os.WriteFile(filename, data, os.FileMode(perm))
}

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

	// Initialize CLI
	cli, err := NewCLI(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize CLI: %v", err)
	}
	defer cli.Close()

	command = commandArgs[0]

	switch command {
	case "tree":
		cli.runTreeCommand()
	case "certificate", "cert":
		if len(commandArgs) < 2 {
			printCertificateUsage()
			os.Exit(1)
		}
		cli.runCertificateCommand(commandArgs[1:])
	case "key":
		if len(commandArgs) < 2 {
			printKeyUsage()
			os.Exit(1)
		}
		cli.runKeyCommand(commandArgs[1:])
	case "create-root":
		cli.runCreateRootCommand()
	case "create-intermediate":
		cli.runCreateIntermediateCommand()
	case "create-leaf":
		cli.runCreateLeafCommand()
	case "export-pkcs12":
		cli.runExportPKCS12Command()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func NewCLI(dbPath string) (*CLI, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	dbWrapper := &DatabaseWrapper{DB: db}
	cm := NewCertificateManager(dbWrapper)
	cm.SetFileWriter(&OSFileWriter{})

	if err := cm.InitializeDatabase(); err != nil {
		db.Close()
		return nil, err
	}

	return &CLI{
		cm:     cm,
		dbPath: dbPath,
	}, nil
}

func (cli *CLI) Close() {
	cli.cm.db.Close()
}

func printUsage() {
	fmt.Println("Usage: vibecert [global-options] <command> [subcommand] [arguments]")
	fmt.Println("")
	fmt.Println("Global options:")
	fmt.Println("  --db <path>      Path to SQLite database file")
	fmt.Println("")
	fmt.Println("Available commands:")
	fmt.Println("  tree                Display certificate dependency tree")
	fmt.Println("")
	fmt.Println("Certificate operations:")
	fmt.Println("  certificate import  Import certificate from file")
	fmt.Println("  certificate export  Export certificate with human-readable content")
	fmt.Println("  certificate delete  Delete certificate and its private key")
	fmt.Println("")
	fmt.Println("Key operations:")
	fmt.Println("  key import          Import private key from file")
	fmt.Println("  key export          Export private key")
	fmt.Println("  key reencrypt       Change private key password")
	fmt.Println("")
	fmt.Println("Certificate Creation:")
	fmt.Println("  create-root         Generate a new root certificate and key")
	fmt.Println("  create-intermediate Generate an intermediate CA certificate")
	fmt.Println("  create-leaf         Generate an end-entity certificate")
	fmt.Println("")
	fmt.Println("Other operations:")
	fmt.Println("  export-pkcs12       Export certificate and key as PKCS#12 file")
	fmt.Println("  help                Show this help message")
	fmt.Println("")
	fmt.Println("Database location:")
	fmt.Printf("  Default: %s\n", getDefaultDatabasePath())
	fmt.Println("  Override with --db flag or VIBECERT_DB environment variable")
	fmt.Println("")
	fmt.Println("For command-specific help, use: vibecert <command> --help")
}

func printCertificateUsage() {
	fmt.Println("Usage: vibecert certificate <subcommand> [arguments]")
	fmt.Println("")
	fmt.Println("Available subcommands:")
	fmt.Println("  import    Import certificate from file")
	fmt.Println("  export    Export certificate with human-readable content")
	fmt.Println("  delete    Delete certificate and its private key")
	fmt.Println("")
	fmt.Println("For subcommand-specific help, use: vibecert certificate <subcommand> --help")
}

func printKeyUsage() {
	fmt.Println("Usage: vibecert key <subcommand> [arguments]")
	fmt.Println("")
	fmt.Println("Available subcommands:")
	fmt.Println("  import     Import private key from file")
	fmt.Println("  export     Export private key")
	fmt.Println("  reencrypt  Change private key password")
	fmt.Println("")
	fmt.Println("For subcommand-specific help, use: vibecert key <subcommand> --help")
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

func (cli *CLI) runTreeCommand() {
	certificates, err := cli.cm.GetAllCertificates()
	if err != nil {
		log.Fatalf("Failed to load certificates: %v", err)
	}

	tree := cli.cm.BuildCertificateTree(certificates)
	cli.printCertificateTree(tree, 0)
}

func (cli *CLI) printCertificateTree(certificates []*Certificate, indent int) {
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
			cli.printCertificateTree(cert.Children, indent+1)
		}
	}
}

func (cli *CLI) runCertificateCommand(args []string) {
	if len(args) == 0 {
		printCertificateUsage()
		os.Exit(1)
	}

	subcommand := args[0]
	switch subcommand {
	case "import":
		cli.runCertificateImportCommand(args[1:])
	case "export":
		cli.runCertificateExportCommand(args[1:])
	case "delete":
		cli.runCertificateDeleteCommand(args[1:])
	case "help", "-h", "--help":
		printCertificateUsage()
	default:
		fmt.Printf("Unknown certificate subcommand: %s\n\n", subcommand)
		printCertificateUsage()
		os.Exit(1)
	}
}

func (cli *CLI) runKeyCommand(args []string) {
	if len(args) == 0 {
		printKeyUsage()
		os.Exit(1)
	}

	subcommand := args[0]
	switch subcommand {
	case "import":
		cli.runKeyImportCommand(args[1:])
	case "export":
		cli.runKeyExportCommand(args[1:])
	case "reencrypt":
		cli.runKeyReencryptCommand(args[1:])
	case "help", "-h", "--help":
		printKeyUsage()
	default:
		fmt.Printf("Unknown key subcommand: %s\n\n", subcommand)
		printKeyUsage()
		os.Exit(1)
	}
}

func (cli *CLI) runCertificateImportCommand(args []string) {
	fs := flag.NewFlagSet("certificate import", flag.ExitOnError)

	var (
		certFile = fs.String("cert", "", "Certificate file path (required)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert certificate import [flags]")
		fmt.Println("")
		fmt.Println("Import a certificate from file.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

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

	cert, err := cli.cm.ImportCertificate(string(certData))
	if err != nil {
		log.Fatalf("Failed to import certificate: %v", err)
	}

	fmt.Printf("Certificate imported successfully:\n")
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Key Hash: %s\n", cert.KeyHash)
	if cert.KeyHash != "" {
		fmt.Printf("  Private key: found matching key\n")
	} else {
		fmt.Printf("  Private key: not found (import key separately)\n")
	}
}

func (cli *CLI) runKeyImportCommand(args []string) {
	fs := flag.NewFlagSet("key import", flag.ExitOnError)

	var (
		keyFile = fs.String("key", "", "Private key file path (required)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert key import [flags]")
		fmt.Println("")
		fmt.Println("Import a private key from file. The key will be automatically")
		fmt.Println("linked to any matching certificates.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *keyFile == "" {
		fmt.Println("Error: key file is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load private key
	keyBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("Failed to read key file: %v", err)
	}

	keyData := string(keyBytes)
	var keyHash string

	// Check if the key is encrypted and get password if needed
	block, _ := pem.Decode(keyBytes)
	if block != nil && x509.IsEncryptedPEMBlock(block) {
		fmt.Print("Private key is encrypted. Enter password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		fmt.Println()

		keyHash, err = cli.cm.ImportKeyWithPassword(keyData, string(passwordBytes))
		if err != nil {
			log.Fatalf("Failed to import key: %v", err)
		}
	} else {
		keyHash, err = cli.cm.ImportKey(keyData)
		if err != nil {
			log.Fatalf("Failed to import key: %v", err)
		}
	}

	fmt.Printf("Private key imported successfully:\n")
	fmt.Printf("  Key Hash: %s\n", keyHash)

	// Check if any certificates were linked
	rows, err := cli.cm.db.Query("SELECT serial_number, subject FROM certificates WHERE key_hash = ?", keyHash)
	if err == nil {
		defer rows.Close()
		linkedCerts := 0
		fmt.Printf("  Linked certificates:\n")
		for rows.Next() {
			var serial, subject string
			if rows.Scan(&serial, &subject) == nil {
				fmt.Printf("    - %s (%s)\n", subject, serial)
				linkedCerts++
			}
		}
		if linkedCerts == 0 {
			fmt.Printf("    - No matching certificates found\n")
		}
	}
}

func (cli *CLI) runCertificateExportCommand(args []string) {
	fs := flag.NewFlagSet("certificate export", flag.ExitOnError)

	var (
		serial     = fs.String("serial", "", "Certificate serial number (required)")
		outputFile = fs.String("output", "", "Output file path (default: {serial}.txt)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert certificate export [flags]")
		fmt.Println("")
		fmt.Println("Export certificate with human-readable content similar to 'openssl x509 -text'.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *serial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Determine output file
	outputPath := *outputFile
	if outputPath == "" {
		outputPath = fmt.Sprintf("%s.txt", *serial)
	}

	err := cli.cm.ExportCertificateToFile(*serial, outputPath)
	if err != nil {
		log.Fatalf("Failed to export certificate: %v", err)
	}

	fmt.Printf("Certificate exported to: %s\n", outputPath)
}

func (cli *CLI) runKeyExportCommand(args []string) {
	fs := flag.NewFlagSet("key export", flag.ExitOnError)

	var (
		serial     = fs.String("serial", "", "Certificate serial number (required)")
		outputFile = fs.String("output", "", "Output key file path (default: {serial}.key)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert key export [flags]")
		fmt.Println("")
		fmt.Println("Export encrypted private key for a certificate.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *serial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Determine output file
	outputPath := *outputFile
	if outputPath == "" {
		outputPath = fmt.Sprintf("%s.key", *serial)
	}

	err := cli.cm.ExportPrivateKeyToFile(*serial, outputPath)
	if err != nil {
		log.Fatalf("Failed to export private key: %v", err)
	}

	fmt.Printf("Private key exported to: %s\n", outputPath)
}

func (cli *CLI) runKeyReencryptCommand(args []string) {
	fs := flag.NewFlagSet("key reencrypt", flag.ExitOnError)

	var (
		serial = fs.String("serial", "", "Certificate serial number (required)")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert key reencrypt [flags]")
		fmt.Println("")
		fmt.Println("Change the password of an encrypted private key.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *serial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Get current password
	fmt.Print("Enter current password: ")
	currentPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read current password: %v", err)
	}
	fmt.Println()

	// Get new password
	fmt.Print("Enter new password: ")
	newPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read new password: %v", err)
	}
	fmt.Println()

	fmt.Print("Confirm new password: ")
	confirmPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password confirmation: %v", err)
	}
	fmt.Println()

	newPassword := string(newPasswordBytes)
	if newPassword != string(confirmPasswordBytes) {
		log.Fatalf("Passwords do not match")
	}

	err = cli.cm.ReencryptPrivateKey(*serial, string(currentPasswordBytes), newPassword)
	if err != nil {
		log.Fatalf("Failed to reencrypt private key: %v", err)
	}

	fmt.Printf("Private key password changed successfully for certificate %s\n", *serial)
}

func (cli *CLI) runCertificateDeleteCommand(args []string) {
	fs := flag.NewFlagSet("certificate delete", flag.ExitOnError)

	var (
		serial = fs.String("serial", "", "Certificate serial number to delete (required)")
		force  = fs.Bool("force", false, "Skip confirmation prompt")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert certificate delete [flags]")
		fmt.Println("")
		fmt.Println("Delete a certificate and optionally its private key.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	fs.Parse(args)

	if *serial == "" {
		fmt.Println("Error: serial number is required")
		fs.Usage()
		os.Exit(1)
	}

	// Get certificate info before deletion
	cert, err := cli.cm.GetCertificate(*serial)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	// Show what will be deleted
	fmt.Printf("Certificate to delete:\n")
	fmt.Printf("  Serial: %s\n", *serial)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	if cert.KeyHash != "" {
		fmt.Printf("  Private key: Yes (will also be deleted)\n")
	} else {
		fmt.Printf("  Private key: No\n")
	}
	fmt.Println()

	// Confirmation prompt unless --force is used
	if !*force {
		fmt.Print("Are you sure you want to delete this certificate? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" && response != "yes" && response != "Yes" {
			fmt.Println("Delete cancelled.")
			os.Exit(0)
		}
	}

	result, err := cli.cm.DeleteCertificate(*serial, *force)
	if err != nil {
		log.Fatalf("Failed to delete certificate: %v", err)
	}

	if result.ChildrenCount > 0 && !*force {
		fmt.Printf("Warning: This certificate is a parent to %d other certificate(s).\n", result.ChildrenCount)
		fmt.Println("Deleting it may leave orphaned certificates in the database.")
		fmt.Print("Continue with deletion anyway? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" && response != "yes" && response != "Yes" {
			fmt.Println("Delete cancelled.")
			os.Exit(0)
		}

		// Retry deletion with force
		result, err = cli.cm.DeleteCertificate(*serial, true)
		if err != nil {
			log.Fatalf("Failed to delete certificate: %v", err)
		}
	}

	if result.KeyDeleted {
		fmt.Printf("✓ Associated private key deleted\n")
	} else if result.KeyPreserved {
		fmt.Printf("✓ Private key preserved (used by %d other certificate(s))\n", result.KeyUsageCount)
	}

	fmt.Printf("✓ Certificate deleted successfully\n")
	fmt.Printf("  Serial: %s\n", *serial)
	fmt.Printf("  Subject: %s\n", result.Subject)
}

func (cli *CLI) runCreateRootCommand() {
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

	// Prompt for password
	fmt.Print("Enter password to encrypt private key: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println()
	password := string(passwordBytes)

	if len(password) == 0 {
		fmt.Println("Error: password cannot be empty")
		os.Exit(1)
	}

	req := &CreateRootCARequest{
		CommonName: *commonName,
		KeySize:    *keySize,
		ValidDays:  *validDays,
		Password:   password,
	}

	cert, err := cli.cm.CreateRootCA(req)
	if err != nil {
		log.Fatalf("Failed to create root CA: %v", err)
	}

	fmt.Printf("Root CA certificate generated successfully:\n")
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Valid for: %d days\n", *validDays)
}

func (cli *CLI) runCreateIntermediateCommand() {
	fmt.Println("create-intermediate command not yet implemented")
}

func (cli *CLI) runCreateLeafCommand() {
	fmt.Println("create-leaf command not yet implemented")
}

func (cli *CLI) runExportPKCS12Command() {
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

	// Load certificate
	cert, err := cli.cm.GetCertificate(*certSerial)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	if cert.KeyHash == "" {
		log.Fatalf("No private key associated with certificate %s", *certSerial)
	}

	// Get private key with password
	fmt.Print("Enter password for private key: ")
	keyPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read key password: %v", err)
	}
	fmt.Println()

	keyData, err := cli.cm.ExportPrivateKey(*certSerial)
	if err != nil {
		log.Fatalf("Failed to get private key: %v", err)
	}

	privateKey, err := cli.cm.loadPrivateKeyFromPEM(keyData, string(keyPasswordBytes))
	if err != nil {
		log.Fatalf("Failed to decrypt private key: %v", err)
	}

	// Prompt for PKCS#12 export password
	fmt.Print("Enter password for PKCS#12 file: ")
	p12PasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
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

	// For now, create PKCS#12 with just the certificate
	var caCerts []*x509.Certificate
	if *includeCACerts {
		// TODO: Implement CA certificate chain collection
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
