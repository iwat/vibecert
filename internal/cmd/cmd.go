package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/iwat/vibecert/internal/application"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
	"github.com/iwat/vibecert/internal/infrastructure/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	_ "github.com/mattn/go-sqlite3"
)

type AppBuilder struct {
	dbPath     string
	fileReader application.FileReader
	fileWriter application.FileWriter
	app        *application.App
}

func NewAppBuilder() *AppBuilder {
	return &AppBuilder{}
}

func (b *AppBuilder) WithDBPath(path string) *AppBuilder {
	b.dbPath = path
	return b
}

func (b *AppBuilder) WithFileReader(reader application.FileReader) *AppBuilder {
	b.fileReader = reader
	return b
}

func (b *AppBuilder) WithFileWriter(writer application.FileWriter) *AppBuilder {
	b.fileWriter = writer
	return b
}

func (b *AppBuilder) Build() error {
	dir := filepath.Dir(b.dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create database directory %s: %v", dir, err)
	}

	db, err := sql.Open("sqlite3", b.dbPath)
	if err != nil {
		return err
	}
	b.app = application.NewApp(dblib.New(db), &tui.TerminalPasswordReader{}, b.fileReader, b.fileWriter)
	return nil
}

func (b *AppBuilder) App(ctx context.Context) *application.App {
	b.app.Initialize(ctx)
	return b.app
}

func RootCmd(appBuilder *AppBuilder) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "vibecert",
		Short: "VibeCert is a certificate manager",
		Long:  "VibeCert is a certificate manager",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			appBuilder.WithDBPath(cmd.Flag("db").Value.String())
			err := appBuilder.Build()
			if err != nil {
				return err
			}
			return nil
		},
	}
	rootFlags := pflag.NewFlagSet("root", pflag.ContinueOnError)
	rootFlags.String("db", getDefaultDatabasePath(), "Path to SQLite database file")
	rootCmd.PersistentFlags().AddFlagSet(rootFlags)

	rootCmd.AddCommand(certificateCmd(appBuilder))
	rootCmd.AddCommand(keyCmd(appBuilder))

	return rootCmd
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
