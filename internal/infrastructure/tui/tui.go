package tui

import (
	"fmt"

	"golang.org/x/term"
)

// TerminalPasswordReader implements PasswordReader using terminal input
type TerminalPasswordReader struct{}

func (r *TerminalPasswordReader) ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	passwordBytes, err := term.ReadPassword(0)
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(passwordBytes), nil
}
