package application

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/iwat/vibecert/internal/domain"
)

type KeyInfo struct {
	KeyPair      *domain.KeyPair
	Certificates []*domain.Certificate
}

func (app *App) ListKeys(ctx context.Context) ([]KeyInfo, error) {
	keys, err := app.db.AllKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %v", err)
	}
	var keyInfos []KeyInfo
	for _, key := range keys {
		certs, err := app.db.CertificatesByPublicKeyHash(ctx, key.PublicKeyHash)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificates by public key hash: %v", err)
		}
		keyInfo := KeyInfo{
			KeyPair:      key,
			Certificates: certs,
		}
		keyInfos = append(keyInfos, keyInfo)
	}

	return keyInfos, nil
}

// ImportKey imports a private key, calculating its hash from the key itself
func (app *App) ImportKeys(ctx context.Context, filename string) ([]*domain.KeyPair, error) {
	pemBytes, err := app.fileReader.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	var importedKeys []*domain.KeyPair

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
				return nil, fmt.Errorf("failed to read password: %v", err)
			}
			keyPair, err = domain.KeyPairFromPEM(block, currentPassword)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %v", err)
			}
		}
		importedKey, err := tx.CreateKey(ctx, keyPair)
		if err != nil {
			return nil, fmt.Errorf("failed to create key: %v", err)
		}
		importedKeys = append(importedKeys, importedKey)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}
	return importedKeys, nil
}

// ReencryptPrivateKey changes the password of the specified private key
func (app *App) ReencryptPrivateKey(ctx context.Context, id int) error {
	key, err := app.db.KeyByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to load private key: %v", err)
	}

	var currentPassword []byte
	if key.IsEncrypted() {
		for {
			currentPassword, err = app.passwordReader.ReadPassword("Enter current password: ")
			if err != nil {
				return fmt.Errorf("failed to read current password: %v", err)
			}
			_, err = key.Decrypt(currentPassword)
			if err == nil {
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
	if !bytes.Equal(newPassword, newPassword2) {
		return errors.New("passwords do not match")
	}

	err = key.Reencrypt(currentPassword, newPassword)
	if err != nil {
		return fmt.Errorf("failed to reencrypt private key: %v", err)
	}

	err = app.db.UpdateKeyPEM(ctx, key.ID, key.PEMData)
	if err != nil {
		return fmt.Errorf("failed to update private key: %v", err)
	}

	return nil
}

// ExportPrivateKey exports the private key for a certificate
func (app *App) ExportPrivateKey(ctx context.Context, id int) (string, error) {
	key, err := app.db.KeyByID(ctx, id)
	if err != nil {
		return "", err
	}

	return key.PEMData, nil
}
