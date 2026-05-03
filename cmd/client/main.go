package main

import (
	"flag"
	"fmt"
	"os"
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

func cmdRegister(c *client.Client) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	username := fs.String("username", "", "username for the new account")
	fs.Parse(os.Args[2:])

	if *username == "" {
		fmt.Fprintln(os.Stderr, "usage: client register -username <name>")
		os.Exit(1)
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

	if err := c.Register(*username, pw); err != nil {
		fatal(err)
	}
}

func cmdLogin(c *client.Client) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	username := fs.String("username", "", "username")
	fs.Parse(os.Args[2:])

	if *username == "" {
		fmt.Fprintln(os.Stderr, "usage: client login -username <name>")
		os.Exit(1)
	}

	pw, err := readPassword("password: ")
	if err != nil {
		fatal(err)
	}

	if err := c.Login(*username, pw); err != nil {
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
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	to := fs.String("to", "", "recipient username")
	fs.Parse(os.Args[2:])

	if *to == "" || fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: client send -to <username> <file>")
		os.Exit(1)
	}

	if err := c.Send(*to, fs.Arg(0)); err != nil {
		fatal(err)
	}
}

func cmdList(c *client.Client) {
	if err := c.ListTransfers(); err != nil {
		fatal(err)
	}
}

func cmdReceive(c *client.Client) {
	fs := flag.NewFlagSet("receive", flag.ExitOnError)
	id := fs.String("id", "", "transfer ID")
	out := fs.String("out", "", "output file path (default: original filename)")
	fs.Parse(os.Args[2:])

	if *id == "" {
		fmt.Fprintln(os.Stderr, "usage: client receive -id <transfer-id> [-out <file>]")
		os.Exit(1)
	}

	if err := c.Receive(*id, *out); err != nil {
		fatal(err)
	}
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
  client <command> [flags]

identity:
  register  -username <name>          create a new account
  login     -username <name>          authenticate and save credentials
  logout                              remove saved credentials
  whoami                              print the logged-in user

keys:
  keygen                              generate RSA-2048 key pair (stored locally)
  upload-key                          upload public key to server

files:
  send      -to <username> <file>     encrypt and send a file
  list                                list files received by you
  receive   -id <id> [-out <file>]    download, verify, and decrypt a file

environment:
  SERVER_URL   server base URL (default: http://localhost:8080)

local files:
  ~/.config/whisper/credentials.json  auth token
  ~/.config/whisper/keys/private.pem  RSA private key (never leaves this machine)
  ~/.config/whisper/keys/public.pem   RSA public key
`)
}
