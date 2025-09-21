package application

// FileWriter interface for abstracting file operations
type FileWriter interface {
	WriteFile(filename string, data []byte, perm int) error
}

// FileReader interface for abstracting file operations
type FileReader interface {
	ReadFile(filename string) ([]byte, error)
}
