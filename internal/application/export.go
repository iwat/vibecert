package application

import (
	"context"
)

// ExportCertificateText exports certificate in human-readable format
func (app *App) ExportCertificateText(ctx context.Context, id int) (string, error) {
	cert, err := app.db.CertificateByID(ctx, id)
	if err != nil {
		return "", err
	}

	return cert.Text(), nil
}

// ExportCertificateToFile exports certificate to a file
func (app *App) ExportCertificateToFile(ctx context.Context, id int, filename string) error {
	text, err := app.ExportCertificateText(ctx, id)
	if err != nil {
		return err
	}

	return app.fileWriter.WriteFile(filename, []byte(text), 0644)
}

// ExportPrivateKey exports the private key for a certificate
func (app *App) ExportPrivateKey(ctx context.Context, id int) (string, error) {
	key, err := app.db.KeyByID(ctx, id)
	if err != nil {
		return "", err
	}

	return key.PEMData, nil
}

// ExportPrivateKeyToFile exports private key to a file
func (app *App) ExportPrivateKeyToFile(ctx context.Context, id int, filename string) error {
	keyData, err := app.ExportPrivateKey(ctx, id)
	if err != nil {
		return err
	}

	return app.fileWriter.WriteFile(filename, []byte(keyData), 0600)
}
