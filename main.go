package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

type Certificate struct {
	Subject      string
	Issuer       string
	SerialNum    string
	FilePath     string
	X509Cert     *x509.Certificate
	Children     []*Certificate
	IsSelfSigned bool
	IsRoot       bool
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "tree":
		runTreeCommand()
	case "create-root":
		runCreateRootCommand()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: vibecert <command> [arguments]")
	fmt.Println("")
	fmt.Println("Available commands:")
	fmt.Println("  tree        Display certificate dependency tree")
	fmt.Println("  create-root Generate a new root certificate and key")
	fmt.Println("  help        Show this help message")
	fmt.Println("")
	fmt.Println("For command-specific help, use: vibecert <command> --help")
}

func runTreeCommand() {
	certs, err := loadCertificates("data/certs")
	if err != nil {
		log.Fatal("Error loading certificates:", err)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found in data/certs directory")
		return
	}

	tree := buildCertificateTree(certs)
	printCertificateTree(tree, 0)
}

func loadCertificates(dirPath string) ([]*Certificate, error) {
	var certificates []*Certificate

	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Check if file has certificate extension
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".crt" && ext != ".cer" && ext != ".pem" {
			return nil
		}

		cert, err := loadCertificate(path)
		if err != nil {
			fmt.Printf("Warning: Could not load certificate from %s: %v\n", path, err)
			return nil
		}

		certificates = append(certificates, cert)
		return nil
	})

	return certificates, err
}

func loadCertificate(filePath string) (*Certificate, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Try to decode PEM first
	block, _ := pem.Decode(data)
	var certData []byte

	if block != nil && block.Type == "CERTIFICATE" {
		certData = block.Bytes
	} else {
		// Assume DER format
		certData = data
	}

	x509Cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, err
	}

	// Extract last 4 bytes of serial number as hex
	serialBytes := x509Cert.SerialNumber.Bytes()
	var lastFourBytes string
	if len(serialBytes) >= 4 {
		lastFourBytes = fmt.Sprintf("%02x%02x%02x%02x",
			serialBytes[len(serialBytes)-4],
			serialBytes[len(serialBytes)-3],
			serialBytes[len(serialBytes)-2],
			serialBytes[len(serialBytes)-1])
	} else {
		// If serial number is less than 4 bytes, use all of it
		lastFourBytes = fmt.Sprintf("%x", x509Cert.SerialNumber)
	}

	isSelfSigned := x509Cert.Subject.String() == x509Cert.Issuer.String()

	cert := &Certificate{
		Subject:      x509Cert.Subject.String(),
		Issuer:       x509Cert.Issuer.String(),
		SerialNum:    lastFourBytes,
		FilePath:     filePath,
		X509Cert:     x509Cert,
		Children:     make([]*Certificate, 0),
		IsSelfSigned: isSelfSigned,
		IsRoot:       false,
	}

	return cert, nil
}

func buildCertificateTree(certs []*Certificate) []*Certificate {
	// Create a map for quick lookup by subject
	subjectMap := make(map[string]*Certificate)
	for _, cert := range certs {
		subjectMap[cert.Subject] = cert
	}

	var roots []*Certificate

	// Build parent-child relationships
	for _, cert := range certs {
		// If issuer equals subject, it's a self-signed root certificate
		if cert.IsSelfSigned {
			cert.IsRoot = true
			roots = append(roots, cert)
		} else {
			// Find parent certificate by matching issuer with subject
			if parent, exists := subjectMap[cert.Issuer]; exists {
				parent.Children = append(parent.Children, cert)
			} else {
				// No parent found, treat as root (externally signed certificate)
				cert.IsRoot = true
				roots = append(roots, cert)
			}
		}
	}

	// Sort roots and children for consistent output
	sortCertificates(roots)
	for _, cert := range certs {
		sortCertificates(cert.Children)
	}

	return roots
}

func sortCertificates(certs []*Certificate) {
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].Subject < certs[j].Subject
	})
}

func printCertificateTree(certs []*Certificate, level int) {
	for _, cert := range certs {
		indent := strings.Repeat("  ", level)
		indicator := ""

		if cert.IsRoot {
			if cert.IsSelfSigned {
				indicator = " [SELF-SIGNED]"
			} else {
				indicator = " [EXTERNALLY SIGNED]"
			}
		}

		fmt.Printf("%s%s (...%s)%s\n", indent, cert.Subject, cert.SerialNum, indicator)

		if len(cert.Children) > 0 {
			printCertificateTree(cert.Children, level+1)
		}
	}
}

func runCreateRootCommand() {
	fs := flag.NewFlagSet("create-root", flag.ExitOnError)

	var (
		keyType      = fs.String("key-type", "ecc", "Key type: ecc, rsa-2048, rsa-3072, or rsa-4096")
		commonName   = fs.String("cn", "", "Common Name (required)")
		organization = fs.String("org", "", "Organization name (required)")
		country      = fs.String("country", "", "Country code (required, e.g., US)")
		validDays    = fs.Int("valid-days", 3650, "Certificate validity period in days")
		keyCertSign  = fs.Bool("key-cert-sign", true, "Allow certificate signing")
		crlSign      = fs.Bool("crl-sign", true, "Allow CRL signing")
		ocspSign     = fs.Bool("ocsp-sign", true, "Allow OCSP signing")
		pathLen      = fs.Int("path-len", 1, "Maximum path length constraint")
	)

	fs.Usage = func() {
		fmt.Println("Usage: vibecert create-root [flags]")
		fmt.Println("")
		fmt.Println("Generate a new root certificate and private key.")
		fmt.Println("")
		fmt.Println("Flags:")
		fs.PrintDefaults()
	}

	// Parse arguments starting from index 2 (skip "vibecert" and "create-root")
	fs.Parse(os.Args[2:])

	if *commonName == "" || *organization == "" || *country == "" {
		fmt.Println("Error: cn, org, and country are required")
		fmt.Println("Example: --cn 'My Root CA' --org 'My Organization' --country US")
		fs.Usage()
		os.Exit(1)
	}

	// Ensure directories exist
	if err := os.MkdirAll("data/certs", 0755); err != nil {
		log.Fatalf("Failed to create data/certs directory: %v", err)
	}
	if err := os.MkdirAll("data/keys", 0755); err != nil {
		log.Fatalf("Failed to create data/keys directory: %v", err)
	}

	// Generate unique serial number
	serialNum, err := generateUniqueSerial()
	if err != nil {
		log.Fatalf("Failed to generate unique serial number: %v", err)
	}

	// Prompt for password
	fmt.Print("Enter password to encrypt private key: ")
	passwordBytes, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Println() // Add newline after password input
	password := string(passwordBytes)

	if len(password) == 0 {
		fmt.Println("Error: password cannot be empty")
		os.Exit(1)
	}

	// Generate key pair
	var privateKey interface{}

	switch *keyType {
	case "ecc":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa-2048":
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		privateKey, err = rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		fmt.Printf("Error: unsupported key type '%s'\n", *keyType)
		fmt.Println("Supported types: ecc, rsa-2048, rsa-3072, rsa-4096")
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create subject distinguished name
	subjectDN := pkix.Name{
		CommonName:   *commonName,
		Organization: []string{*organization},
		Country:      []string{*country},
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNum,
		Subject:      subjectDN,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, *validDays),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            *pathLen,
		MaxPathLenZero:        *pathLen == 0,
	}

	// Set key usage based on flags
	if *keyCertSign {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if *crlSign {
		template.KeyUsage |= x509.KeyUsageCRLSign
	}
	if *ocspSign {
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
	}

	// Generate certificate (self-signed for root)
	var publicKey interface{}
	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Generate file names based on serial number
	serialStr := fmt.Sprintf("%x", serialNum)
	keyFile := filepath.Join("data", "keys", fmt.Sprintf("%s.key", serialStr))
	certFile := filepath.Join("data", "certs", fmt.Sprintf("%s.crt", serialStr))

	// Save private key (encrypted)
	if err := saveEncryptedPrivateKey(keyFile, privateKey, password); err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	// Save certificate
	if err := saveCertificate(certFile, certBytes); err != nil {
		log.Fatalf("Failed to save certificate: %v", err)
	}

	fmt.Printf("Root certificate and key generated successfully:\n")
	fmt.Printf("  Private key: %s (encrypted)\n", keyFile)
	fmt.Printf("  Certificate: %s\n", certFile)
	fmt.Printf("  Serial number: %s\n", serialStr)
	fmt.Printf("  Key type: %s\n", *keyType)
	fmt.Printf("  Valid for: %d days\n", *validDays)
}

func generateUniqueSerial() (*big.Int, error) {
	// Generate a random 128-bit serial number
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(128), nil).Sub(max, big.NewInt(1))

	for {
		serial, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}

		// Check if files with this serial already exist
		serialStr := fmt.Sprintf("%x", serial)
		keyFile := filepath.Join("data", "keys", fmt.Sprintf("%s.key", serialStr))
		certFile := filepath.Join("data", "certs", fmt.Sprintf("%s.crt", serialStr))

		// If neither file exists, we can use this serial number
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			if _, err := os.Stat(certFile); os.IsNotExist(err) {
				return serial, nil
			}
		}

		// If files exist, try again with a new random number
	}
}

func saveEncryptedPrivateKey(filename string, key interface{}, password string) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	var keyBytes []byte
	var keyType string

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		keyType = "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		keyType = "RSA PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported key type")
	}

	if err != nil {
		return err
	}

	// Encrypt the key with the password
	block, err := x509.EncryptPEMBlock(rand.Reader, keyType, keyBytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return err
	}

	return pem.Encode(keyFile, block)
}

func saveCertificate(filename string, certBytes []byte) error {
	certFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
}
