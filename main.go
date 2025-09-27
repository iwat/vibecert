package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/iwat/vibecert/internal/application"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
	"github.com/iwat/vibecert/internal/infrastructure/tui"

	_ "github.com/mattn/go-sqlite3"
)

// CLI wraps the certificate manager with command-line interface
type CLI struct {
	app *application.App
}

// OSFileWriter implements FileWriter using os.WriteFile
type OSFileWriter struct{}

func (w *OSFileWriter) WriteFile(filename string, data []byte, perm int) error {
	return os.WriteFile(filename, data, os.FileMode(perm))
}

type OSFileReader struct{}

func (r *OSFileReader) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
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

	command = commandArgs[0]

	ctx := context.Background()

	switch command {
	case "certificate", "cert":
		if len(commandArgs) < 2 {
			printCertificateUsage()
			os.Exit(1)
		}
		cli.runCertificateCommand(ctx, commandArgs[1:])
	case "key":
		if len(commandArgs) < 2 {
			printKeyUsage()
			os.Exit(1)
		}
		cli.runKeyCommand(ctx, commandArgs[1:])
	case "create-root":
		cli.runCreateRootCommand(ctx)
	case "create-intermediate":
		cli.runCreateIntermediateCommand()
	case "create-leaf":
		cli.runCreateLeafCommand()
	case "export-pkcs12":
		cli.runExportPKCS12Command(ctx)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func NewCLI(dbPath string) (*CLI, error) {
	ctx := context.Background()

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	q := dblib.New(db)
	if err := q.InitializeDatabase(ctx); err != nil {
		db.Close()
		return nil, err
	}

	app := application.NewApp(q, &tui.TerminalPasswordReader{}, &OSFileReader{}, &OSFileWriter{})

	return &CLI{
		app: app,
	}, nil
}

func printUsage() {
	fmt.Println("Usage: vibecert [global-options] <command> [subcommand] [arguments]")
	fmt.Println("")
	fmt.Println("Global options:")
	fmt.Println("  --db <path>      Path to SQLite database file")
	fmt.Println("")
	fmt.Println("Certificate operations:")
	fmt.Println("  certificate tree    Display certificate dependency tree")
	fmt.Println("  certificate import  Import certificate from file")
	fmt.Println("  certificate export  Export certificate with human-readable content")
	fmt.Println("  certificate delete  Delete certificate and its dedicated private key")
	fmt.Println("")
	fmt.Println("Key operations:")
	fmt.Println("  key import          Import private key from file")
	fmt.Println("  key export          Export private key")
	fmt.Println("  key reencrypt       Change private key password")
	fmt.Println("  key delete          Delete private key")
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
	fmt.Println("  tree      Display certificate dependency tree")
	fmt.Println("  import    Import certificate from file")
	fmt.Println("  export    Export certificate with human-readable content")
	fmt.Println("  delete    Delete certificate and its dedicated private key")
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
	fmt.Println("  delete     Delete private key")
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

func (cli *CLI) runTreeCommand(ctx context.Context) {
	tree := cli.app.BuildCertificateTree(ctx)
	cli.printCertificateTree(tree, 0)
}

func (cli *CLI) printCertificateTree(certificates []*application.CertificateNode, indent int) {
	indentStr := strings.Repeat("  ", indent)

	for _, cert := range certificates {
		marker := "├─"
		if indent == 0 {
			marker = "└─"
		}

		keyStatus := "No Key"
		if cert.Certificate.PublicKeyHash != "" {
			keyStatus = "Has Key"
		}

		fmt.Printf("%s%s %s (id: %d) [%s]\n",
			indentStr, marker, cert.Certificate.SubjectDN, cert.Certificate.ID, keyStatus)

		if len(cert.Children) > 0 {
			cli.printCertificateTree(cert.Children, indent+1)
		}
	}
}

func (cli *CLI) runCertificateCommand(ctx context.Context, args []string) {
	if len(args) == 0 {
		printCertificateUsage()
		os.Exit(1)
	}

	subcommand := args[0]
	switch subcommand {
	case "tree":
		cli.runTreeCommand(ctx)
	case "import":
		cli.runCertificateImportCommand(ctx, args[1:])
	case "export":
		cli.runCertificateExportCommand(ctx, args[1:])
	case "delete":
		cli.runCertificateDeleteCommand(ctx, args[1:])
	case "help", "-h", "--help":
		printCertificateUsage()
	default:
		fmt.Printf("Unknown certificate subcommand: %s\n\n", subcommand)
		printCertificateUsage()
		os.Exit(1)
	}
}

func (cli *CLI) runKeyCommand(ctx context.Context, args []string) {
	if len(args) == 0 {
		printKeyUsage()
		os.Exit(1)
	}

	subcommand := args[0]
	switch subcommand {
	case "import":
		cli.runKeyImportCommand(ctx, args[1:])
	case "export":
		cli.runKeyExportCommand(ctx, args[1:])
	case "reencrypt":
		cli.runKeyReencryptCommand(ctx, args[1:])
	case "help", "-h", "--help":
		printKeyUsage()
	default:
		fmt.Printf("Unknown key subcommand: %s\n\n", subcommand)
		printKeyUsage()
		os.Exit(1)
	}
}

func (cli *CLI) runCertificateImportCommand(ctx context.Context, args []string) {
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

	importedCerts, err := cli.app.ImportCertificates(ctx, *certFile)
	if err != nil {
		log.Fatalf("Failed to import certificate(s): %v", err)
	}

	fmt.Printf("Certificate imported successfully:\n")
	for _, cert := range importedCerts {
		fmt.Printf("%d) %s\n", cert.ID, cert.SubjectDN)
	}
}

func (cli *CLI) runKeyImportCommand(ctx context.Context, args []string) {
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

	importedKeys, err := cli.app.ImportKeys(ctx, *keyFile)
	if err != nil {
		log.Fatalf("Failed to import key: %v", err)
	}

	fmt.Printf("Private key imported successfully:\n")
	for _, k := range importedKeys {
		fmt.Printf("%d) %s (%s, %d bits)\n", k.ID, k.PublicKeyHash, k.KeyType, k.KeySize)
	}
}

func (cli *CLI) runCertificateExportCommand(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("certificate export", flag.ExitOnError)

	var (
		id = fs.Int("id", -1, "Certificate id (required)")
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

	if *id == -1 {
		fmt.Println("Error: certificate id is required")
		fs.Usage()
		os.Exit(1)
	}

	pem, err := cli.app.ExportCertificate(ctx, *id)
	if err != nil {
		log.Fatalf("Failed to export certificate: %v", err)
	}
	fmt.Println(pem)
}

func (cli *CLI) runKeyExportCommand(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("key export", flag.ExitOnError)

	var (
		id = fs.Int("id", -1, "Key id (required)")
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

	if *id == -1 {
		fmt.Println("Error: key id is required")
		fs.Usage()
		os.Exit(1)
	}

	pem, err := cli.app.ExportPrivateKey(ctx, *id)
	if err != nil {
		log.Fatalf("Failed to export private key: %v", err)
	}
	fmt.Println(pem)
}

func (cli *CLI) runKeyReencryptCommand(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("key reencrypt", flag.ExitOnError)

	var (
		id = fs.Int("id", -1, "Key id (required)")
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

	if *id == -1 {
		fmt.Println("Error: key id is required")
		fs.Usage()
		os.Exit(1)
	}

	err := cli.app.ReencryptPrivateKey(ctx, *id)
	if err != nil {
		log.Fatalf("Failed to reencrypt private key: %v", err)
	}

	fmt.Printf("Private key password changed successfully for key %d\n", *id)
}

func (cli *CLI) runCertificateDeleteCommand(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("certificate delete", flag.ExitOnError)

	var (
		id    = fs.Int("id", -1, "Certificate id to delete (required)")
		force = fs.Bool("force", false, "Skip confirmation prompt")
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

	if *id == -1 {
		fmt.Println("Error: certificate id is required")
		fs.Usage()
		os.Exit(1)
	}

	result, err := cli.app.DeleteCertificate(ctx, *id, *force)
	if err != nil {
		log.Fatalf("Failed to delete certificate: %v", err)
	}

	fmt.Println(result)
}

func (cli *CLI) runCreateRootCommand(ctx context.Context) {
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

	cert, _, err := cli.app.CreateCA(ctx, &application.CreateCARequest{
		CommonName: *commonName,
		KeySize:    *keySize,
		ValidDays:  *validDays,
	})
	if err != nil {
		log.Fatalf("Failed to create root CA: %v", err)
	}

	fmt.Printf("Root CA certificate generated successfully:\n")
	fmt.Printf("  Serial: %s\n", cert.SerialNumber)
}

func (cli *CLI) runCreateIntermediateCommand() {
	fmt.Println("create-intermediate command not yet implemented")
}

func (cli *CLI) runCreateLeafCommand() {
	fmt.Println("create-leaf command not yet implemented")
}

func (cli *CLI) runExportPKCS12Command(ctx context.Context) {
	fs := flag.NewFlagSet("export-pkcs12", flag.ExitOnError)

	var (
		id         = fs.Int("id", -1, "Certificate id to export (required)")
		outputFile = fs.String("output", "", "Output PKCS#12 file path (default: {serial}.p12)")
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

	if *id == -1 {
		fmt.Println("Error: certificate id is required")
		fs.Usage()
		os.Exit(1)
	}

	err := cli.app.ExportCertificateWithKeyToPKCS12(ctx, *id, *outputFile)
	if err != nil {
		log.Fatalf("Failed to export certificate: %v", err)
	}
}
