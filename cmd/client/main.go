package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"whisper/internal/client"
	"whisper/internal/config"
)

func main() {
	cfg := config.LoadClient()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	c := client.New(cfg.ServerURL)
	cmd := os.Args[1]

	switch cmd {
	case "init":
		cmdInit(c)
	case "register":
		cmdRegister(c)
	case "login":
		cmdLogin(c)
	case "logout":
		cmdLogout()
	case "whoami":
		cmdWhoami(c)
	case "keygen":
		cmdKeygen(c)
	case "upload-key":
		cmdUploadKey(c)
	case "send":
		cmdSend(c)
	case "list":
		cmdList(c)
	case "receive":
		cmdReceive(c)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func cmdInit(c *client.Client) {
	fmt.Println("=== whisper init ===")

	alreadyRegistered, err := readConfirm("already have an account? [y/N]: ")
	if err != nil {
		fatal(err)
	}

	username, err := readLine("username: ")
	if err != nil {
		fatal(err)
	}
	pw, err := readPassword("password: ")
	if err != nil {
		fatal(err)
	}

	step := 1
	total := 3
	if !alreadyRegistered {
		total = 4
		confirm, err := readPassword("confirm password: ")
		if err != nil {
			fatal(err)
		}
		if pw != confirm {
			fatal(fmt.Errorf("passwords do not match"))
		}

		fmt.Printf("\n[%d/%d] registering account...\n", step, total)
		if err := c.Register(username, pw); err != nil {
			fatal(err)
		}
		step++
	}

	fmt.Printf("[%d/%d] logging in...\n", step, total)
	if err := c.Login(username, pw); err != nil {
		fatal(err)
	}
	step++

	fmt.Printf("[%d/%d] generating RSA-2048 key pair...\n", step, total)
	if err := c.Keygen(); err != nil {
		fatal(err)
	}
	step++

	fmt.Printf("[%d/%d] uploading public key to server...\n", step, total)
	if err := c.UploadPublicKey(); err != nil {
		fatal(err)
	}

	fmt.Printf("\nready. logged in as %q with keys on server.\n", username)
}

func cmdRegister(c *client.Client) {
	username, err := readLine("username: ")
	if err != nil {
		fatal(err)
	}
	pw, err := readPassword("password: ")
	if err != nil {
		fatal(err)
	}
	confirm, err := readPassword("confirm password: ")
	if err != nil {
		fatal(err)
	}
	if pw != confirm {
		fatal(fmt.Errorf("passwords do not match"))
	}

	if err := c.Register(username, pw); err != nil {
		fatal(err)
	}
}

func cmdLogin(c *client.Client) {
	username, err := readLine("username: ")
	if err != nil {
		fatal(err)
	}
	pw, err := readPassword("password: ")
	if err != nil {
		fatal(err)
	}

	if err := c.Login(username, pw); err != nil {
		fatal(err)
	}
}

func cmdLogout() {
	if err := client.DeleteCredentials(); err != nil {
		fatal(err)
	}
	fmt.Println("logged out")
}

func cmdWhoami(c *client.Client) {
	if err := c.Me(); err != nil {
		fatal(err)
	}
}

func cmdKeygen(c *client.Client) {
	if err := c.Keygen(); err != nil {
		fatal(err)
	}
}

func cmdUploadKey(c *client.Client) {
	if err := c.UploadPublicKey(); err != nil {
		fatal(err)
	}
}

func cmdSend(c *client.Client) {
	to, err := readLine("recipient username: ")
	if err != nil {
		fatal(err)
	}
	filePath, err := readLine("file path: ")
	if err != nil {
		fatal(err)
	}

	if err := c.Send(to, filePath); err != nil {
		fatal(err)
	}
}

func cmdList(c *client.Client) {
	if err := c.ListTransfers(); err != nil {
		fatal(err)
	}
}

func cmdReceive(c *client.Client) {
	id, err := readLine("transfer ID: ")
	if err != nil {
		fatal(err)
	}
	out, err := readLine("output path (leave blank for original filename): ")
	if err != nil {
		fatal(err)
	}

	if err := c.Receive(id, out); err != nil {
		fatal(err)
	}
}

func readConfirm(prompt string) (bool, error) {
	answer, err := readLine(prompt)
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("unexpected EOF")
	}
	return strings.TrimSpace(scanner.Text()), nil
}

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(pw), nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Print(`whisper — end-to-end encrypted file transfer

usage:
  client <command>

quickstart:
  init                                register, generate keys, upload in one step

identity:
  register                            create a new account (interactive)
  login                               authenticate and save credentials (interactive)
  logout                              remove saved credentials
  whoami                              print the logged-in user

keys:
  keygen                              generate RSA-2048 key pair (stored locally)
  upload-key                          upload public key to server

files:
  send                                encrypt and send a file (interactive)
  list                                list files received by you
  receive                             download, verify, and decrypt a file (interactive)

environment:
  SERVER_URL   server base URL (default: http://localhost:8080)

local files:
  ~/.config/whisper/credentials.json  auth token
  ~/.config/whisper/keys/private.pem  RSA private key (never leaves this machine)
  ~/.config/whisper/keys/public.pem   RSA public key
`)
}
