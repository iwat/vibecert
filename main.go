package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
