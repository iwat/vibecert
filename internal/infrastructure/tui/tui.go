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

type TerminalConfirmer struct{}

// Confirm prompts the user with a message and waits for a Y/N response.
func (c *TerminalConfirmer) Confirm(message string) bool {
	fmt.Print(message + " (y/N) ")

	var response string
	fmt.Scanln(&response)
	return response == "Y" || response == "y"
}
