package application

import (
	"context"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/iwat/vibecert/internal/domain"
)

// BuildCertificateTree builds a hierarchical tree of certificates
func (app *App) BuildCertificateTree(ctx context.Context) []*CertificateNode {
	certs, err := app.db.AllCertificates(ctx)
	if err != nil {
		return nil
	}
	return app.buildCertificateTree(ctx, certs)
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

// DeleteCertificate deletes a certificate and optionally its key
func (app *App) DeleteCertificate(ctx context.Context, id int, force bool) (*DeleteResult, error) {
	cert, err := app.db.CertificateByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate with id %d not found", id)
		}
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	slog.Info("initial certificate", "cert", cert)

	var allCerts = []*domain.Certificate{cert}
	var remainingCerts = []*domain.Certificate{cert}
	for len(remainingCerts) > 0 {
		var next []*domain.Certificate
		for _, cert := range remainingCerts {
			childCerts, err := app.db.CertificatesByIssuerAndAuthorityKeyID(ctx, cert.SubjectDN, cert.SubjectKeyID)
			if err != nil {
				return nil, fmt.Errorf("failed to load child certificates: %v", err)
			}
			allCerts = append(allCerts, childCerts...)
			next = append(next, childCerts...)
		}
		remainingCerts = next
	}
	slog.Debug("loaded certificates", "count", len(allCerts))

	nodes := app.buildCertificateTree(ctx, allCerts)
	for _, node := range nodes {
		fmt.Println(node)
	}
	ok := app.confirmer.Confirm("Delete the above certificates?")
	if !ok {
		return nil, ErrCancelled
	}

	result := &DeleteResult{
		Subject: cert.SubjectDN,
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}
	result.CertificateDeleted = true
	return result, err
}

func (app *App) buildCertificateTree(ctx context.Context, certs []*domain.Certificate) []*CertificateNode {
	var nodes []*CertificateNode
	for _, cert := range certs {
		key, err := app.db.KeyByPublicKeyHash(ctx, cert.PublicKeyHash)
		if err != nil {
			key = nil
		}
		nodes = append(nodes, &CertificateNode{cert, key, nil})
	}

	var roots []*CertificateNode
	for _, node := range nodes {
		if node.Certificate.IsSelfSigned() {
			roots = append(roots, node)
		} else {
			// Find parent by matching issuer
			parentFound := false
			for _, parent := range nodes {
				if parent.Certificate.SubjectDN == node.Certificate.IssuerDN &&
					parent.Certificate.SubjectKeyID == node.Certificate.AuthorityKeyID {
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

	return roots
}

type CertificateNode struct {
	Certificate *domain.Certificate
	Key         *domain.Key
	Children    []*CertificateNode
}

func (n *CertificateNode) String() string {
	return n.string("")
}

func (n *CertificateNode) string(prefix string) string {
	var output strings.Builder
	output.WriteString(prefix)
	output.WriteString(n.Certificate.String())
	for _, child := range n.Children {
		output.WriteRune('\n')
		output.WriteString(child.string(prefix + "  "))
	}
	return output.String()
}
