package application

import (
	"sort"

	"github.com/iwat/vibecert/internal/domain"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
)

// CertificateManager handles all certificate operations
type CertificateManager struct {
	db *dblib.Queries
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(db *dblib.Queries) *CertificateManager {
	return &CertificateManager{
		db: db,
	}
}

type CertificateNode struct {
	Certificate *domain.Certificate
	Children    []*CertificateNode
}

// BuildCertificateTree builds a hierarchical tree of certificates
func (cm *CertificateManager) BuildCertificateTree(certificates []*domain.Certificate) []*CertificateNode {
	var nodes []*CertificateNode
	for _, cert := range certificates {
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

func sortCertificates(certificates []*CertificateNode) {
	sort.Slice(certificates, func(i, j int) bool {
		return certificates[i].Certificate.SubjectDN < certificates[j].Certificate.SubjectDN
	})
}
