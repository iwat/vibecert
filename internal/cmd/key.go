package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func keyCmd(appBuilder *AppBuilder) *cobra.Command {
	keyCmd := &cobra.Command{
		Use:   "key",
		Short: "Manage private keys",
		Long:  "Manage private keys",
	}

	keyCmd.AddCommand(keyListCmd(appBuilder))
	keyCmd.AddCommand(keyImportCmd(appBuilder))
	keyCmd.AddCommand(keyExportCmd(appBuilder))
	keyCmd.AddCommand(keyReencryptCmd(appBuilder))
	keyCmd.AddCommand(keyDeleteCmd(appBuilder))

	return keyCmd
}

func keyListCmd(appBuilder *AppBuilder) *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "list",
		Short: "List private keys",
		Long:  "List private keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			keyInfos, err := appBuilder.App(cmd.Context()).ListKeys(cmd.Context())
			if err != nil {
				return err
			}

			for _, k := range keyInfos {
				fmt.Printf("%d) %s (%s, %d bits)\n",
					k.KeyPair.ID, k.KeyPair.PublicKeyHash, k.KeyPair.KeyType, k.KeyPair.KeySize)
				for _, cert := range k.Certificates {
					fmt.Printf("  (cert id: %d) %s\n", cert.ID, cert.SubjectDN)
				}
			}
			return nil
		},
	}

	return importCmd
}

func keyImportCmd(appBuilder *AppBuilder) *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import a private key",
		Long:  "Import a private key",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var file string
			if len(args) == 0 {
				file = "-"
			} else {
				file = args[0]
			}
			importedKeys, err := appBuilder.App(cmd.Context()).ImportKeys(cmd.Context(), file)
			if err != nil {
				return err
			}

			fmt.Printf("Private key imported successfully:\n")
			for _, k := range importedKeys {
				fmt.Printf("%d) %s (%s, %d bits)\n", k.ID, k.PublicKeyHash, k.KeyType, k.KeySize)
			}
			return nil
		},
	}

	return importCmd
}

func keyExportCmd(appBuilder *AppBuilder) *cobra.Command {
	var id int
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export a private key",
		Long:  "Export a private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			pem, err := appBuilder.App(cmd.Context()).ExportPrivateKey(cmd.Context(), id)
			if err != nil {
				return err
			}
			fmt.Println(pem)
			return nil
		},
	}
	exportCmd.Flags().IntVar(&id, "id", -1, "Private key ID")
	exportCmd.MarkFlagRequired("id")

	return exportCmd
}

func keyReencryptCmd(appBuilder *AppBuilder) *cobra.Command {
	var id int
	reencryptCmd := &cobra.Command{
		Use:   "reencrypt",
		Short: "Reencrypt a private key",
		Long:  "Reencrypt a private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := appBuilder.App(cmd.Context()).ReencryptPrivateKey(cmd.Context(), id)
			if err != nil {
				return err
			}

			fmt.Printf("Private key password changed successfully for key %d\n", id)
			return nil
		},
	}
	reencryptCmd.Flags().IntVar(&id, "id", -1, "Private key ID")
	reencryptCmd.MarkFlagRequired("id")

	return reencryptCmd
}

func keyDeleteCmd(appBuilder *AppBuilder) *cobra.Command {
	var id int
	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a private key",
		Long:  "Delete a private key",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}
	deleteCmd.Flags().IntVar(&id, "id", -1, "Private key ID")
	deleteCmd.MarkFlagRequired("id")

	return deleteCmd
}
