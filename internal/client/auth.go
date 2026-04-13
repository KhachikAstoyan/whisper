package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Client struct {
	ServerURL  string
	httpClient *http.Client
}

func New(serverURL string) *Client {
	return &Client{
		ServerURL:  serverURL,
		httpClient: &http.Client{},
	}
}

func (c *Client) Register(username, password string) error {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	resp, err := c.httpClient.Post(
		c.ServerURL+"/api/v1/auth/register",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)

	if resp.StatusCode != http.StatusCreated {
		if msg, ok := res["error"]; ok {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("registration failed (HTTP %d)", resp.StatusCode)
	}
	fmt.Printf("registered: username=%q id=%s\n", res["username"], res["id"])
	return nil
}

func (c *Client) Login(username, password string) error {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	resp, err := c.httpClient.Post(
		c.ServerURL+"/api/v1/auth/login",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)

	if resp.StatusCode != http.StatusOK {
		if msg, ok := res["error"]; ok {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("login failed (HTTP %d)", resp.StatusCode)
	}
	token, ok := res["token"]
	if !ok || token == "" {
		return fmt.Errorf("server returned no token")
	}
	if err := SaveCredentials(&Credentials{Username: username, Token: token}); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	fmt.Printf("logged in as %q — credentials saved\n", username)
	return nil
}

func (c *Client) Me() error {
	creds, err := LoadCredentials()
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, c.ServerURL+"/api/v1/auth/me", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var res map[string]string
	json.NewDecoder(resp.Body).Decode(&res)

	if resp.StatusCode != http.StatusOK {
		if msg, ok := res["error"]; ok {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("request failed (HTTP %d)", resp.StatusCode)
	}
	fmt.Printf("logged in as %q (id: %s)\n", res["username"], res["id"])
	return nil
}
