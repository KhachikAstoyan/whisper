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

func keysDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "whisper", "keys"), nil
}

// Keygen generates a fresh RSA-2048 key pair and saves it locally.
func (c *Client) Keygen() error {
	dir, err := keysDir()
	if err != nil {
		return err
	}
	priv, err := cryptopkg.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keys: %w", err)
	}
	if err := cryptopkg.SaveKeyPair(dir, priv); err != nil {
		return fmt.Errorf("save keys: %w", err)
	}
	fmt.Printf("RSA-2048 key pair saved to %s\n", dir)
	return nil
}

// UploadPublicKey sends the locally stored public key to the server.
func (c *Client) UploadPublicKey() error {
	creds, err := LoadCredentials()
	if err != nil {
		return err
	}
	dir, err := keysDir()
	if err != nil {
		return err
	}
	pubPEM, err := cryptopkg.LoadPublicKeyPEM(dir)
	if err != nil {
		return fmt.Errorf("load public key (run 'keygen' first): %w", err)
	}

	body, _ := json.Marshal(map[string]string{"public_key": string(pubPEM)})
	req, err := http.NewRequest(http.MethodPut, c.ServerURL+"/api/v1/keys", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res map[string]string
		json.NewDecoder(resp.Body).Decode(&res)
		if msg, ok := res["error"]; ok {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("upload failed (HTTP %d)", resp.StatusCode)
	}
	fmt.Println("public key uploaded to server")
	return nil
}

// RecipientKey holds the server's response for a public-key lookup.
type RecipientKey struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

// GetRecipientKey fetches another user's public key by username.
func (c *Client) GetRecipientKey(username string) (*RecipientKey, error) {
	resp, err := c.httpClient.Get(c.ServerURL + "/api/v1/keys/" + username)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var res map[string]string
		json.NewDecoder(resp.Body).Decode(&res)
		if msg, ok := res["error"]; ok {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, fmt.Errorf("key lookup failed (HTTP %d)", resp.StatusCode)
	}
	var rk RecipientKey
	json.NewDecoder(resp.Body).Decode(&rk)
	return &rk, nil
}

// getKeyByUserID fetches a user's public key by their UUID (used when receiving files).
func (c *Client) getKeyByUserID(token, userID string) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, c.ServerURL+"/api/v1/keys/id/"+userID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)
	if resp.StatusCode != http.StatusOK {
		if msg, ok := res["error"]; ok {
			return "", fmt.Errorf("%s", msg)
		}
		return "", fmt.Errorf("key lookup failed (HTTP %d)", resp.StatusCode)
	}
	return res["public_key"], nil
}
