package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	cryptopkg "whisper/internal/crypto"
)

// Send encrypts filePath for recipientUsername and uploads it to the server.
func (c *Client) Send(recipientUsername, filePath string) error {
	creds, err := LoadCredentials()
	if err != nil {
		return err
	}
	dir, err := keysDir()
	if err != nil {
		return err
	}
	senderPriv, err := cryptopkg.LoadPrivateKey(dir)
	if err != nil {
		return fmt.Errorf("load private key (run 'keygen' first): %w", err)
	}

	recipientKey, err := c.GetRecipientKey(recipientUsername)
	if err != nil {
		return fmt.Errorf("get recipient key: %w", err)
	}
	recipientPub, err := cryptopkg.ParsePublicKey([]byte(recipientKey.PublicKey))
	if err != nil {
		return fmt.Errorf("parse recipient public key: %w", err)
	}

	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	senderID, err := c.fetchUserID(creds.Token)
	if err != nil {
		return fmt.Errorf("get sender id: %w", err)
	}

	pkg, err := cryptopkg.Pack(plaintext, filepath.Base(filePath), senderID, recipientKey.UserID, senderPriv, recipientPub)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	body, err := json.Marshal(pkg)
	if err != nil {
		return fmt.Errorf("marshal package: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.ServerURL+"/api/v1/transfers", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()

	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)

	if resp.StatusCode != http.StatusCreated {
		if msg, ok := res["error"]; ok {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("upload failed (HTTP %d)", resp.StatusCode)
	}
	fmt.Printf("file sent — transfer id: %s\n", res["id"])
	return nil
}

// TransferItem is the list entry returned by the server.
type TransferItem struct {
	ID        string `json:"id"`
	SenderID  string `json:"sender_id"`
	Filename  string `json:"filename"`
	CreatedAt string `json:"created_at"`
}

// ListTransfers prints all transfers received by the logged-in user.
func (c *Client) ListTransfers() error {
	creds, err := LoadCredentials()
	if err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodGet, c.ServerURL+"/api/v1/transfers", nil)
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("list failed (HTTP %d)", resp.StatusCode)
	}
	var items []TransferItem
	json.NewDecoder(resp.Body).Decode(&items)
	if len(items) == 0 {
		fmt.Println("no transfers")
		return nil
	}
	fmt.Printf("%-36s  %-30s  %-36s  %s\n", "ID", "FILENAME", "FROM", "SENT AT")
	fmt.Printf("%s\n", "----------------------------------------------------------------------------------------------------")
	for _, t := range items {
		fmt.Printf("%-36s  %-30s  %-36s  %s\n", t.ID, t.Filename, t.SenderID, t.CreatedAt)
	}
	return nil
}

// Receive downloads and decrypts a transfer, writing plaintext to outputPath.
// If outputPath is empty, the original filename from the package is used.
func (c *Client) Receive(transferID, outputPath string) error {
	creds, err := LoadCredentials()
	if err != nil {
		return err
	}
	dir, err := keysDir()
	if err != nil {
		return err
	}
	recipientPriv, err := cryptopkg.LoadPrivateKey(dir)
	if err != nil {
		return fmt.Errorf("load private key (run 'keygen' first): %w", err)
	}

	req, _ := http.NewRequest(http.MethodGet, c.ServerURL+"/api/v1/transfers/"+transferID, nil)
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res map[string]string
		json.NewDecoder(resp.Body).Decode(&res)
		if msg, ok := res["error"]; ok {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("download failed (HTTP %d)", resp.StatusCode)
	}

	var pkg cryptopkg.EncryptedPackage
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return fmt.Errorf("parse package: %w", err)
	}

	senderKeyPEM, err := c.getKeyByUserID(creds.Token, pkg.SenderID)
	if err != nil {
		return fmt.Errorf("get sender public key: %w", err)
	}
	senderPub, err := cryptopkg.ParsePublicKey([]byte(senderKeyPEM))
	if err != nil {
		return fmt.Errorf("parse sender public key: %w", err)
	}

	plaintext, err := cryptopkg.Unpack(&pkg, senderPub, recipientPriv)
	if err != nil {
		return fmt.Errorf("decrypt/verify: %w", err)
	}

	outPath := outputPath
	if outPath == "" {
		outPath = pkg.Filename
	}
	if err := os.WriteFile(outPath, plaintext, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	fmt.Printf("signature verified — file saved to %s\n", outPath)
	return nil
}

func (c *Client) fetchUserID(token string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, c.ServerURL+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	if id, ok := res["id"]; ok && id != "" {
		return id, nil
	}
	return "", fmt.Errorf("could not retrieve user id")
}
