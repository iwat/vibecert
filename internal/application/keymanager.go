package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/iwat/vibecert/internal/domain"
)

type KeyInfo struct {
	Key          *domain.Key
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
			Key:          key,
			Certificates: certs,
		}
		keyInfos = append(keyInfos, keyInfo)
	}

	return keyInfos, nil
}

// ImportKey imports a private key, calculating its hash from the key itself
func (app *App) ImportKeys(ctx context.Context, filename string) ([]*domain.Key, error) {
	pemBytes, err := app.fileReader.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	var importedKeys []*domain.Key

	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}

		key, err := domain.KeyFromUnencryptedPEM(block)
		if err == domain.ErrEncryptedPrivateKey {
			currentPassword, err := app.passwordReader.ReadPassword("Entry current password: ")
			if err != nil {
				return nil, fmt.Errorf("failed to read password: %v", err)
			}
			key, err = domain.KeyFromPEM(block, currentPassword)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %v", err)
			}
		}
		importedKey, err := tx.CreateKey(ctx, key)
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
func (app *App) ExportPrivateKey(ctx context.Context, id int, decrypt bool) (string, error) {
	key, err := app.db.KeyByID(ctx, id)
	if err != nil {
		return "", err
	}

	if decrypt {
		decryptedKey, err := app.tryDecryptPrivateKey(key, "the key")
		if err != nil {
			return "", fmt.Errorf("failed to decrypt private key: %v", err)
		}
		var block pem.Block
		switch typedKey := decryptedKey.(type) {
		case *rsa.PrivateKey:
			block.Type = "RSA PRIVATE KEY"
			block.Bytes = x509.MarshalPKCS1PrivateKey(typedKey)
		case *ecdsa.PrivateKey:
			keyBytes, err := x509.MarshalECPrivateKey(typedKey)
			if err != nil {
				return "", fmt.Errorf("failed to marshal EC private key: %v", err)
			}
			block.Type = "EC PRIVATE KEY"
			block.Bytes = keyBytes
		default:
			return "", fmt.Errorf("unsupported key type: %T", typedKey)
		}
		return string(pem.EncodeToMemory(&block)), nil
	}

	return key.PEMData, nil
}

func (app *App) DeleteKey(ctx context.Context, id int, force bool) error {
	key, err := app.db.KeyByID(ctx, id)
	if err != nil {
		return err
	}

	fmt.Println(key)

	certs, err := app.db.CertificatesByPublicKeyHash(ctx, key.PublicKeyHash)
	if err != nil {
		return err
	}
	if len(certs) > 0 {
		for _, cert := range certs {
			fmt.Println("-", cert)
		}
		return errors.New("key is in use")
	}
	fmt.Println("No certificates using this key")

	if !force {
		ok := app.confirmer.Confirm("Delete the key?")
		if !ok {
			return ErrCancelled
		}
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	err = tx.DeleteKey(ctx, key.ID)
	if err != nil {
		return fmt.Errorf("failed to delete key: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	return err
}

func (app *App) PruneUnusedKeys(ctx context.Context, force bool) error {
	keys, err := app.db.AllKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to load keys: %v", err)
	}

	var unusedKeys []*domain.Key
	for _, key := range keys {
		certs, err := app.db.CertificatesByPublicKeyHash(ctx, key.PublicKeyHash)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			unusedKeys = append(unusedKeys, key)
			fmt.Println(key)
		}
	}

	if len(unusedKeys) == 0 {
		fmt.Println("No unused keys found")
		return nil
	}

	if !force {
		ok := app.confirmer.Confirm("Delete the above keys?")
		if !ok {
			return ErrCancelled
		}
	}

	tx := app.db.Begin(ctx)
	defer tx.Rollback()

	for _, key := range unusedKeys {
		err := tx.DeleteKey(ctx, key.ID)
		if err != nil {
			return fmt.Errorf("failed to delete unused key: %v", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	return err
}

func (app *App) CreateKey(ctx context.Context, keySpec KeySpec) (*domain.Key, error) {
	newPassword, err := app.askPasswordWithConfirmation("Password for the key")
	if err != nil {
		return nil, fmt.Errorf("failed to ask for new password: %v", err)
	}

	key, err := keySpec.Key(newPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	_, err = app.db.CreateKey(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %v", err)
	}

	return key, nil
}
