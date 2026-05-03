# Whisper — End-to-End Encrypted File Transfer

A working prototype of a secure file-transfer system written entirely in Go.  
Files are encrypted client-side before upload. The server stores only ciphertext and never sees plaintext.

---

## Cryptographic Design

| Concern | Primitive |
|---|---|
| File encryption | AES-256-GCM |
| Key encapsulation | RSA-OAEP (SHA-256) |
| Authentication / integrity | RSA-PSS (SHA-256) |
| Password hashing | Argon2id |
| Session tokens | HMAC-SHA-256 JWT (24 h) |

### Package format

Every transfer is a self-contained JSON object:

```json
{
  "sender_id":     "<uuid>",
  "recipient_id":  "<uuid>",
  "filename":      "report.pdf",
  "timestamp":     1714900000,
  "encrypted_key": "<base64 — RSA-OAEP(aes_key, recipient_pub)>",
  "nonce":         "<base64 — AES-GCM nonce>",
  "ciphertext":    "<base64 — AES-GCM(plaintext, aes_key, nonce)>",
  "signature":     "<base64 — RSA-PSS(SHA-256(above fields), sender_priv)>"
}
```

The server verifies the signature on upload. The recipient verifies again on download.

### Send flow

```
sender client                        server                   recipient client
─────────────────────────────────────────────────────────────────────────────
GET /keys/{recipient}           ─────────────────────►
                                ◄───────────────────── recipient_pub + user_id
generate random AES-256 key
AES-GCM encrypt file
RSA-OAEP wrap AES key with recipient_pub
RSA-PSS sign package with sender_priv
POST /transfers (JSON package)  ─────────────────────►
                                verify signature server-side
                                write package to disk
                                INSERT transfers row
                                ◄───────────────────── transfer id
```

### Receive flow

```
GET /transfers                  ─────────────────────►
                                ◄───────────────────── list of transfer metadata
GET /transfers/{id}             ─────────────────────►
                                ◄───────────────────── encrypted package JSON
verify RSA-PSS signature with sender_pub
RSA-OAEP unwrap AES key with recipient_priv
AES-GCM decrypt → plaintext
```

---

## Threat Model

| Assumption | Mitigation |
|---|---|
| Server is honest-but-curious | AES-GCM encryption; server never holds the AES key in plaintext |
| Attacker intercepts traffic | Use HTTPS in production; ciphertext is useless without recipient private key |
| Attacker tampers with stored data | RSA-PSS signature detects any modification |
| Attacker impersonates sender | Signature verification requires sender's registered public key |

---

## Project Structure

```
.
├── cmd/
│   ├── server/         # server entrypoint
│   └── client/         # CLI entrypoint
├── internal/
│   ├── config/         # env → typed config struct
│   ├── crypto/         # AES-GCM, RSA-OAEP, RSA-PSS, EncryptedPackage
│   ├── db/             # pgxpool connect + SQL migrations
│   ├── models/         # User, Transfer
│   ├── repository/     # UserRepo, KeyRepo, TransferRepo
│   ├── service/        # AuthService, KeyService, TransferService
│   ├── httpserver/
│   │   ├── handlers/   # auth, keys, transfers
│   │   └── middleware/ # JWT auth middleware
│   └── client/         # HTTP client methods + local key/credential storage
├── .env.example
├── Makefile
└── go.mod
```

---

## Prerequisites

- Go 1.23+
- PostgreSQL 14+

---

## Setup

### 1. Clone and install dependencies

```bash
go mod download
```

### 2. Start PostgreSQL locally

```bash
# macOS with Homebrew
brew services start postgresql@16

# or with Docker
docker run -d \
  --name whisper-pg \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=whisper \
  -p 5432:5432 \
  postgres:16-alpine
```

Create the database if it doesn't exist yet:

```bash
createdb -U postgres whisper
```

### 3. Configure environment

```bash
cp .env.example .env
# edit .env — set JWT_SECRET to a long random string
```

`.env` fields:

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8080` | HTTP listen port |
| `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/whisper?sslmode=disable` | PostgreSQL connection string |
| `STORAGE_PATH` | `./storage` | Directory for encrypted package files |
| `JWT_SECRET` | *(required)* | HMAC key for JWT signing — use `openssl rand -hex 32` |
| `ENV` | `dev` | `dev` or `prod` |

### 4. Build

```bash
make build
# produces bin/server and bin/client
```

### 5. Run the server

```bash
make run-server
# or: source .env && ./bin/server
```

The server auto-runs SQL migrations on startup.

---

## Demo Walkthrough

Open **two terminals** — one for Alice, one for Bob.

### Alice: create identity

```bash
# Register
./bin/client register -username alice
# password: ••••••

# Log in
./bin/client login -username alice
# password: ••••••

# Generate RSA key pair (stored in ~/.config/whisper/keys/)
./bin/client keygen

# Upload public key to server
./bin/client upload-key
```

### Bob: create identity

```bash
./bin/client register -username bob
./bin/client login -username bob
./bin/client keygen
./bin/client upload-key
```

### Alice: send a file to Bob

```bash
echo "This message is for Bob's eyes only." > secret.txt
./bin/client send -to bob secret.txt
# file sent — transfer id: <uuid>
```

### Bob: receive the file

```bash
# List inbox
./bin/client list

# Download, verify signature, decrypt
./bin/client receive -id <uuid> -out received.txt

cat received.txt
# This message is for Bob's eyes only.
```

### Verify the server never saw plaintext

```bash
# The .pkg file on disk is the raw encrypted package:
cat storage/<uuid>.pkg | python3 -m json.tool
# All binary fields are base64-encoded ciphertext — no plaintext visible.
```

---

## API Reference

All endpoints are under `/api/v1`. Authenticated endpoints require `Authorization: Bearer <token>`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/register` | — | Register a new user |
| `POST` | `/auth/login` | — | Authenticate, receive JWT |
| `GET` | `/auth/me` | ✓ | Current user info |
| `PUT` | `/keys` | ✓ | Upload / replace RSA public key |
| `GET` | `/keys/{username}` | — | Fetch public key by username |
| `GET` | `/keys/id/{user_id}` | — | Fetch public key by UUID |
| `POST` | `/transfers` | ✓ | Upload encrypted package |
| `GET` | `/transfers` | ✓ | List transfers for logged-in user |
| `GET` | `/transfers/{id}` | ✓ | Download encrypted package |

---

## CLI Reference

```
client register  -username <name>          create account
client login     -username <name>          authenticate, save token
client logout                              remove saved token
client whoami                              print logged-in user

client keygen                              generate RSA-2048 key pair locally
client upload-key                          push public key to server

client send      -to <username> <file>     encrypt, sign, and upload a file
client list                                list files sent to you
client receive   -id <id> [-out <file>]    download, verify signature, and decrypt
```

Local files written by the client:

| Path | Contents |
|---|---|
| `~/.config/whisper/credentials.json` | Username + JWT (mode 0600) |
| `~/.config/whisper/keys/private.pem` | RSA private key (mode 0600, never uploaded) |
| `~/.config/whisper/keys/public.pem` | RSA public key (mode 0644) |

---

## Running Tests

```bash
go test ./...
```

The crypto package has unit tests covering:

- Full Pack → Unpack round-trip
- Signature rejection when wrong public key is used
- Signature rejection after ciphertext tampering
