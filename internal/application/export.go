package application

import (
	"context"
)

// ExportCertificateText exports certificate in human-readable format
func (app *App) ExportCertificateText(id int) (string, error) {
	cert, err := app.db.CertificateByID(context.TODO(), id)
	if err != nil {
		return "", err
	}

	return cert.Text(), nil
}

// ExportCertificateToFile exports certificate to a file
func (app *App) ExportCertificateToFile(id int, filename string) error {
	text, err := app.ExportCertificateText(id)
	if err != nil {
		return err
	}

	return app.fileWriter.WriteFile(filename, []byte(text), 0644)
}

// ExportPrivateKey exports the private key for a certificate
func (app *App) ExportPrivateKey(id int) (string, error) {
	key, err := app.db.KeyByID(context.TODO(), id)
	if err != nil {
		return "", err
	}

	return key.PEMData, nil
}

// ExportPrivateKeyToFile exports private key to a file
func (app *App) ExportPrivateKeyToFile(id int, filename string) error {
	keyData, err := app.ExportPrivateKey(id)
	if err != nil {
		return err
	}

	return app.fileWriter.WriteFile(filename, []byte(keyData), 0600)
}
