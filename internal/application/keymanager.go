package application

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/iwat/vibecert/internal/domain"
)

// ImportKey imports a private key, calculating its hash from the key itself
func (app *App) ImportKey(filename string) error {
	pemBytes, err := app.fileReader.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}

	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}

		keyPair, err := domain.KeyPairFromUnencryptedPEM(block)
		if err == domain.ErrEncryptedPrivateKey {
			currentPassword, err := app.passwordReader.ReadPassword("Entry current password: ")
			if err != nil {
				return fmt.Errorf("failed to read password: %v", err)
			}
			keyPair, err = domain.KeyPairFromPEM(block, currentPassword)
			if err != nil {
				return fmt.Errorf("failed to decrypt private key: %v", err)
			}
		}
		_, err = app.db.CreateKey(context.TODO(), keyPair)
		if err != nil {
			return fmt.Errorf("failed to create key: %v", err)
		}
	}
	return nil
}

// ReencryptPrivateKey changes the password of the specified private key
func (app *App) ReencryptPrivateKey(id int) error {
	key, err := app.db.KeyByID(context.TODO(), id)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
	}

	var currentPassword string
	if key.IsEncrypted() {
		for {
			currentPassword, err = app.passwordReader.ReadPassword("Enter current password: ")
			if err != nil {
				return fmt.Errorf("failed to read current password: %v", err)
			}
			if key.IsEncryptedWithPassword(currentPassword) {
				break
			}
		}
	}

	newPassword, err := app.passwordReader.ReadPassword("Enter new password: ")
	if err != nil {
		return fmt.Errorf("failed to read new password: %v", err)
	}
	newPassword2, err := app.passwordReader.ReadPassword("Re-enter new password: ")
	if err != nil {
		return fmt.Errorf("failed to read new password: %v", err)
	}
	if newPassword != newPassword2 {
		return errors.New("passwords do not match")
	}

	err = key.Reencrypt(currentPassword, newPassword)
	if err != nil {
		return fmt.Errorf("failed to reencrypt private key: %v", err)
	}

	err = app.db.UpdateKeyPEM(context.TODO(), key.ID, key.PEMData)
	if err != nil {
		return fmt.Errorf("failed to update private key: %v", err)
	}

	return nil
}
