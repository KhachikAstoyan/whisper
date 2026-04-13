package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"

	"whisper/internal/client"
)

const defaultServerURL = "http://localhost:8080"

func main() {
	serverURL := os.Getenv("SERVER_URL")
	if serverURL == "" {
		serverURL = defaultServerURL
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	c := client.New(serverURL)
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
	fmt.Print(`whisper client

usage:
  client <command> [flags]

commands:
  register  -username <name>   create a new account
  login     -username <name>   authenticate and save credentials locally
  logout                       remove saved credentials
  whoami                       print the currently logged-in user

environment:
  SERVER_URL   server base URL (default: http://localhost:8080)

credentials are stored in ~/.config/whisper/credentials.json
`)
}
