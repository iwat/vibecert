package application

import (
	"context"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/iwat/vibecert/internal/domain"
)

// BuildCertificateTree builds a hierarchical tree of certificates
func (app *App) BuildCertificateTree(ctx context.Context) []*CertificateNode {
	certs, err := app.db.AllCertificates(ctx)
	if err != nil {
		return nil
	}
	return app.buildCertificateTree(ctx, certs, make(map[string]*CertificateNode))
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
func (app *App) DeleteCertificate(ctx context.Context, id int, force bool) error {
	cert, err := app.db.CertificateByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("certificate with id %d not found", id)
		}
		return fmt.Errorf("failed to load certificate: %v", err)
	}
	slog.Info("initial certificate", "cert", cert)

	var allCerts = []*domain.Certificate{cert}
	var remainingCerts = []*domain.Certificate{cert}
	for len(remainingCerts) > 0 {
		var next []*domain.Certificate
		for _, cert := range remainingCerts {
			childCerts, err := app.db.CertificatesByIssuerAndAuthorityKeyID(ctx, cert.SubjectDN, cert.SubjectKeyID)
			if err != nil {
				return fmt.Errorf("failed to load child certificates: %v", err)
			}
			allCerts = append(allCerts, childCerts...)
			next = append(next, childCerts...)
		}
		remainingCerts = next
	}
	slog.Debug("loaded certificates", "count", len(allCerts))

	nodes := app.buildCertificateTree(ctx, allCerts, make(map[string]*CertificateNode))
	for _, node := range nodes {
		fmt.Println(node)
	}
	if !force {
		ok := app.confirmer.Confirm("Delete the above certificates?")
		if !ok {
			return ErrCancelled
		}
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	for _, node := range nodes {
		for _, cert := range node.Certificates {
			err := tx.DeleteCertificate(ctx, cert.ID)
			if err != nil {
				return err
			}
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	return err
}

func (app *App) buildCertificateTree(
	ctx context.Context,
	certs []*domain.Certificate,
	lookup map[string]*CertificateNode,
) []*CertificateNode {
	var nodes []*CertificateNode
	for _, cert := range certs {
		key, err := app.db.KeyByPublicKeyHash(ctx, cert.PublicKeyHash)
		if err != nil {
			key = nil
		}
		lookupKey := certificateNodeLookupKey(cert)
		existing := lookup[lookupKey]
		if existing == nil {
			existing = &CertificateNode{
				cert.SubjectDN,
				cert.SubjectKeyID,
				cert.IssuerDN,
				cert.AuthorityKeyID,
				cert.IsSelfSigned(),
				[]*domain.Certificate{cert},
				key,
				nil,
			}
			lookup[lookupKey] = existing
		} else {
			existing.Certificates = append(existing.Certificates, cert)
		}
		nodes = append(nodes, existing)
	}

	var roots []*CertificateNode
	for _, node := range nodes {
		if node.IsSelfSigned {
			roots = append(roots, node)
		} else {
			// Find parent by matching issuer
			parentFound := false
			for _, parent := range nodes {
				if parent.SubjectDN == node.IssuerDN &&
					parent.SubjectKeyID == node.AuthorityKeyID {
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
	SubjectDN      string
	SubjectKeyID   string
	IssuerDN       string
	AuthorityKeyID string
	IsSelfSigned   bool
	Certificates   []*domain.Certificate
	Key            *domain.Key
	Children       []*CertificateNode
}

func (n *CertificateNode) String() string {
	if len(n.Certificates) == 1 {
		return n.Certificates[0].String()
	}
	var ids []string
	for _, c := range n.Certificates {
		ids = append(ids, strconv.Itoa(c.ID))
	}
	return fmt.Sprintf("(📜 %s) %s", strings.Join(ids, ", "), n.SubjectDN)
}

func (n *CertificateNode) string(prefix string) string {
	var output strings.Builder
	output.WriteString(prefix)
	output.WriteString(n.String())
	for _, child := range n.Children {
		output.WriteRune('\n')
		output.WriteString(child.string(prefix + "  "))
	}
	return output.String()
}

func certificateNodeLookupKey(cert *domain.Certificate) string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%t", cert.SubjectDN, cert.SubjectKeyID, cert.IssuerDN, cert.AuthorityKeyID, cert.IsSelfSigned())
}
