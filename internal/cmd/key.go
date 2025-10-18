package cmd

import (
	"fmt"
	"strings"

	"github.com/iwat/vibecert/internal/application"
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
	keyCmd.AddCommand(keyPruneCmd(appBuilder))
	keyCmd.AddCommand(keyCreateCmd(appBuilder))

	return keyCmd
}

func keyListCmd(appBuilder *AppBuilder) *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "list",
		Short: "List private keys",
		Long:  "List private keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			keyInfos, err := appBuilder.App(cmd.Context()).ListKeys(cmd.Context())
			if err != nil {
				return err
			}

			for _, k := range keyInfos {
				fmt.Println(k.Key)
				for _, cert := range k.Certificates {
					fmt.Printf("  %s\n", cert)
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
			cmd.SilenceUsage = true
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
				fmt.Printf("%d) %s (%s)\n", k.ID, k.PublicKeyHash, k.KeySpec)
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
			cmd.SilenceUsage = true
			pem, err := appBuilder.App(cmd.Context()).ExportPrivateKey(cmd.Context(), id)
			if err != nil {
				return err
			}
			fmt.Println(strings.TrimSpace(pem))
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
			cmd.SilenceUsage = true
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
	var (
		id    int
		force bool
	)
	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a private key",
		Long:  "Delete a private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return appBuilder.App(cmd.Context()).DeleteKey(cmd.Context(), id, force)
		},
	}
	deleteCmd.Flags().IntVar(&id, "id", -1, "Private key ID")
	deleteCmd.MarkFlagRequired("id")
	deleteCmd.Flags().BoolVar(&force, "force", false, "Attempt to delete the certificate without prompting for confirmation")

	return deleteCmd
}

func keyPruneCmd(appBuilder *AppBuilder) *cobra.Command {
	var force bool
	deleteCmd := &cobra.Command{
		Use:   "prune",
		Short: "Prune unused private key(s)",
		Long:  "Prune unused private key(s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return appBuilder.App(cmd.Context()).PruneUnusedKeys(cmd.Context(), force)
		},
	}
	deleteCmd.Flags().BoolVar(&force, "force", false, "Attempt to delete the unused keys without prompting for confirmation")

	return deleteCmd
}

func keyCreateCmd(appBuilder *AppBuilder) *cobra.Command {
	var keySpec application.KeySpec
	deleteCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a private key",
		Long:  "Create a private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			key, err := appBuilder.App(cmd.Context()).CreateKey(cmd.Context(), keySpec)
			if err != nil {
				return err
			}
			fmt.Println("Created", key)
			return nil
		},
	}

	deleteCmd.Flags().Var(&keySpec, "keyspec", "Key spec ["+application.KnownKeySpecs()+"]")
	deleteCmd.MarkFlagRequired("keyspec")

	return deleteCmd
}
