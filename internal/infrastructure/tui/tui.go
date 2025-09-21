package tui

import (
	"fmt"

	"golang.org/x/term"
)

// TerminalPasswordReader implements PasswordReader using terminal input
type TerminalPasswordReader struct{}

func (r *TerminalPasswordReader) ReadPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	passwordBytes, err := term.ReadPassword(0)
	if err != nil {
		return nil, err
	}
	fmt.Println()
	return passwordBytes, nil
}
