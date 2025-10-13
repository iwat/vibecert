package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/iwat/vibecert/internal/application"
	"github.com/iwat/vibecert/internal/infrastructure/dblib"
	"github.com/iwat/vibecert/internal/infrastructure/tui"
	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	_ "github.com/mattn/go-sqlite3"
)

type AppBuilder struct {
	dbPath     string
	fileReader application.FileReader
	fileWriter application.FileWriter
	confirmer  application.Confirmer
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

func (b *AppBuilder) WithConfirmer(confirmer application.Confirmer) *AppBuilder {
	b.confirmer = confirmer
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
	b.app = application.NewApp(dblib.New(db), &tui.TerminalPasswordReader{}, b.fileReader, b.fileWriter, b.confirmer)
	return nil
}

func (b *AppBuilder) App(ctx context.Context) *application.App {
	b.app.Initialize(ctx)
	return b.app
}

func RootCmd(appBuilder *AppBuilder) *cobra.Command {
	var db string
	var logLevel = logLevel(slog.LevelWarn)
	rootCmd := &cobra.Command{
		Use:   "vibecert",
		Short: "VibeCert is a certificate manager",
		Long:  "VibeCert is a certificate manager",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			slog.SetDefault(slog.New(
				tint.NewHandler(os.Stderr, &tint.Options{
					Level:      slog.Level(logLevel),
					TimeFormat: time.Kitchen,
				}),
			))

			appBuilder.WithDBPath(db)
			err := appBuilder.Build()
			if err != nil {
				return err
			}
			return nil
		},
	}
	rootFlags := pflag.NewFlagSet("root", pflag.ContinueOnError)
	rootFlags.StringVar(&db, "db", getDefaultDatabasePath(), "Path to SQLite database file")
	rootFlags.Var(&logLevel, "log", "Log level")
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

type logLevel slog.Level

func (l *logLevel) String() string {
	return slog.Level(*l).String()
}

func (l *logLevel) Set(value string) error {
	value = strings.ToLower(value)
	switch value {
	case "debug":
		*l = logLevel(slog.LevelDebug)
	case "info":
		*l = logLevel(slog.LevelInfo)
	case "warn":
		*l = logLevel(slog.LevelWarn)
	case "error":
		*l = logLevel(slog.LevelError)
	default:
		return fmt.Errorf("invalid log level: %s", value)
	}
	return nil
}

func (l *logLevel) Type() string {
	return "log-level"
}
