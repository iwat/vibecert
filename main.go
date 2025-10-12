package main

import (
	"os"

	"github.com/iwat/vibecert/internal/cmd"

	_ "github.com/mattn/go-sqlite3"
)

// OSFileWriter implements FileWriter using os.WriteFile
type OSFileWriter struct{}

func (w *OSFileWriter) WriteFile(filename string, data []byte, perm int) error {
	return os.WriteFile(filename, data, os.FileMode(perm))
}

type OSFileReader struct{}

func (r *OSFileReader) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

var dbPath string

func main() {
	appBuilder := cmd.NewAppBuilder().
		WithFileWriter(&OSFileWriter{}).
		WithFileReader(&OSFileReader{})
	if err := cmd.RootCmd(appBuilder).Execute(); err != nil {
		os.Exit(1)
	}
}
