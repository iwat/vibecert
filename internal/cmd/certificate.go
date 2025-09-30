package cmd

import (
	"fmt"
	"log"

	"github.com/iwat/vibecert/internal/application"
	"github.com/spf13/cobra"
)

func certificateCmd(appBuilder *AppBuilder) *cobra.Command {
	certificateCmd := &cobra.Command{
		Use:   "certificate",
		Short: "Manage certificates",
		Long:  "Manage certificates",
	}

	certificateCmd.AddCommand(certificateTreeCmd(appBuilder))
	certificateCmd.AddCommand(certificateImportCmd(appBuilder))
	certificateCmd.AddCommand(certificateExportCmd(appBuilder))
	certificateCmd.AddCommand(certificateDeleteCmd(appBuilder))
	certificateCmd.AddCommand(certificateCreateRootCmd(appBuilder))
	certificateCmd.AddCommand(certificateCreateIntermediateCmd(appBuilder))
	certificateCmd.AddCommand(certificateCreateLeafCmd(appBuilder))
	certificateCmd.AddCommand(certificateExportPKCS12Cmd(appBuilder))

	return certificateCmd
}

func certificateTreeCmd(appBuilder *AppBuilder) *cobra.Command {
	treeCmd := &cobra.Command{
		Use:   "tree",
		Short: "Display certificate dependency tree",
		Long:  "Display certificate dependency tree",
		RunE: func(cmd *cobra.Command, args []string) error {
			tree := appBuilder.App(cmd.Context()).BuildCertificateTree(cmd.Context())
			printCertificateTree(tree, "")
			return nil
		},
	}

	return treeCmd
}

func certificateImportCmd(appBuilder *AppBuilder) *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import a certificate",
		Long:  "Import a certificate",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var file string
			if len(args) == 0 {
				file = "-"
			} else {
				file = args[0]
			}
			importedCerts, err := appBuilder.App(cmd.Context()).ImportCertificates(cmd.Context(), file)
			if err != nil {
				return err
			}

			fmt.Printf("Certificate imported successfully:\n")
			for _, cert := range importedCerts {
				fmt.Printf("%d) %s\n", cert.ID, cert.SubjectDN)
			}
			return nil
		},
	}

	return importCmd
}

func certificateExportCmd(appBuilder *AppBuilder) *cobra.Command {
	var id int
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export a certificate",
		Long:  "Export a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			pem, err := appBuilder.App(cmd.Context()).ExportCertificate(cmd.Context(), id)
			if err != nil {
				return err
			}
			fmt.Println(pem)
			return nil
		},
	}
	exportCmd.Flags().IntVar(&id, "id", -1, "Certificate ID")
	exportCmd.MarkFlagRequired("id")

	return exportCmd
}

func certificateDeleteCmd(appBuilder *AppBuilder) *cobra.Command {
	var (
		id    int
		force bool
	)
	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a certificate and its dedicated private key",
		Long:  "Delete a certificate and its dedicated private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := appBuilder.App(cmd.Context()).DeleteCertificate(cmd.Context(), id, force)
			if err != nil {
				log.Fatalf("Failed to delete certificate: %v", err)
			}
			fmt.Println(result)
			return nil
		},
	}
	deleteCmd.Flags().IntVar(&id, "id", -1, "Certificate ID")
	deleteCmd.MarkFlagRequired("id")
	deleteCmd.Flags().BoolVar(&force, "force", false, "Unused")

	return deleteCmd
}

func certificateCreateRootCmd(appBuilder *AppBuilder) *cobra.Command {
	var (
		commonName string
		validDays  int
		rsaKeySize int
	)
	createRootCmd := &cobra.Command{
		Use:   "create-root",
		Short: "Create a root certificate",
		Long:  "Create a root certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			cert, _, err := appBuilder.App(cmd.Context()).CreateCA(cmd.Context(), &application.CreateCARequest{
				CommonName: commonName,
				KeySize:    rsaKeySize,
				ValidDays:  validDays,
			})
			if err != nil {
				return err
			}

			fmt.Printf("Root CA certificate generated successfully:\n")
			fmt.Printf("  ID: %d\n", cert.ID)
			fmt.Printf("  Serial: %s\n", cert.SerialNumber)
			return nil
		},
	}
	createRootCmd.Flags().StringVar(&commonName, "cn", "", "Common Name")
	createRootCmd.MarkFlagRequired("cn")
	createRootCmd.Flags().IntVar(&validDays, "valid-days", 3650, "Certificate validity in days")
	createRootCmd.MarkFlagRequired("valid-days")
	createRootCmd.Flags().IntVar(&rsaKeySize, "rsa-key-size", 4096, "RSA key size in bits")

	return createRootCmd
}

func certificateCreateIntermediateCmd(appBuilder *AppBuilder) *cobra.Command {
	createIntermediateCmd := &cobra.Command{
		Use:   "create-intermediate",
		Short: "Create an intermediate certificate",
		Long:  "Create an intermediate certificate",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	return createIntermediateCmd
}

func certificateCreateLeafCmd(appBuilder *AppBuilder) *cobra.Command {
	createLeafCmd := &cobra.Command{
		Use:   "create-leaf",
		Short: "Create a leaf certificate",
		Long:  "Create a leaf certificate",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	return createLeafCmd
}

func certificateExportPKCS12Cmd(appBuilder *AppBuilder) *cobra.Command {
	var (
		id         int
		outputFile string
	)
	exportPKCS12Cmd := &cobra.Command{
		Use:   "export-pkcs12",
		Short: "Export a certificate and its private key as PKCS#12",
		Long:  "Export a certificate and its private key as PKCS#12",
		RunE: func(cmd *cobra.Command, args []string) error {
			return appBuilder.App(cmd.Context()).ExportCertificateWithKeyToPKCS12(cmd.Context(), id, outputFile)
		},
	}
	exportPKCS12Cmd.Flags().IntVar(&id, "id", -1, "Certificate ID")
	exportPKCS12Cmd.MarkFlagRequired("id")
	exportPKCS12Cmd.Flags().StringVar(&outputFile, "output", "", "Output file")
	exportPKCS12Cmd.MarkFlagRequired("output")

	return exportPKCS12Cmd
}

func printCertificateTree(certs []*application.CertificateNode, prefix string) {
	for i, cert := range certs {
		isLast := i == len(certs)-1

		var marker string
		var extension string

		if isLast {
			marker = "└─"
			extension = "  "
		} else {
			marker = "├─"
			extension = "│ "
		}

		keyStatus := "(no key)"
		if cert.KeyPair != nil {
			keyStatus = fmt.Sprintf("(key id: %d)", cert.KeyPair.ID)
		}

		fmt.Printf("%s%s (cert id: %d) %s %s\n",
			prefix, marker, cert.Certificate.ID, cert.Certificate.SubjectDN, keyStatus)

		if len(cert.Children) > 0 {
			newPrefix := prefix + extension
			printCertificateTree(cert.Children, newPrefix)
		}
	}
}
