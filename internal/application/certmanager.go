package application

import (
	"context"
	"encoding/pem"
	"sort"

	"github.com/iwat/vibecert/internal/domain"
)

type CertificateNode struct {
	Certificate *domain.Certificate
	Children    []*CertificateNode
}

// BuildCertificateTree builds a hierarchical tree of certificates
func (app *App) BuildCertificateTree(ctx context.Context) []*CertificateNode {
	certs, err := app.db.AllCertificates(ctx)
	if err != nil {
		return nil
	}

	var nodes []*CertificateNode
	for _, cert := range certs {
		nodes = append(nodes, &CertificateNode{cert, nil})
	}

	var roots []*CertificateNode
	for _, node := range nodes {
		if node.Certificate.IsSelfSigned() {
			roots = append(roots, node)
		} else {
			// Find parent by matching issuer
			parentFound := false
			for _, parent := range nodes {
				if parent.Certificate.SubjectDN == node.Certificate.IssuerDN {
					parent.Children = append(parent.Children, node)
					parentFound = true
					break
				}
			}
			// If no parent found, treat as orphan root
			if !parentFound {
				roots = append(roots, node)
			}
		}
	}

	// Sort certificates
	sortCertificates(roots)
	for _, cert := range nodes {
		sortCertificates(cert.Children)
	}

	return roots
}

// ExportCertificate exports certificate in human-readable format
func (app *App) ExportCertificate(ctx context.Context, id int) (string, error) {
	cert, err := app.db.CertificateByID(ctx, id)
	if err != nil {
		return "", err
	}

	return cert.Text(), nil
}

func (app *App) ImportCertificates(ctx context.Context, filename string) ([]*domain.Certificate, error) {
	data, err := app.fileReader.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var importedCerts []*domain.Certificate

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := domain.CertificateFromPEM(block)
		if err != nil {
			return nil, err
		}

		importedCert, err := tx.CreateCertificate(ctx, cert)
		if err != nil {
			return nil, err
		}
		importedCerts = append(importedCerts, importedCert)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return importedCerts, nil
}

func sortCertificates(certificates []*CertificateNode) {
	sort.Slice(certificates, func(i, j int) bool {
		return certificates[i].Certificate.SubjectDN < certificates[j].Certificate.SubjectDN
	})
}
