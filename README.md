# Whisper — End-to-End Encrypted File Transfer

## Setup

### 1. Install dependencies

```bash
go mod download
```

### 2. Start PostgreSQL

```bash
# macOS
brew services start postgresql@16

# Docker
docker run -d \
  --name whisper-pg \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=whisper \
  -p 5432:5432 \
  postgres:16-alpine
```

```bash
createdb -U postgres whisper
```

### 3. Configure environment

```bash
cp .env.example .env
# set JWT_SECRET: openssl rand -hex 32
```

### 4. Build and start server

```bash
make build
make run-server
```

---

## Demo Walkthrough

Open **two terminals** — one for Alice, one for Bob.

### Alice: create identity

```bash
./bin/client init
# prompts: username, password — registers, generates keys, uploads public key
```

### Bob: create identity

```bash
./bin/client init
# prompts: username, password — registers, generates keys, uploads public key
```

### Alice: send a file to Bob

```bash
echo "This message is for Bob's eyes only." > secret.txt
./bin/client send -to bob secret.txt
# file sent — transfer id: <uuid>
```

### Bob: receive the file

```bash
./bin/client list

./bin/client receive -id <uuid> -out received.txt
cat received.txt
# This message is for Bob's eyes only.
```

### Verify server never saw plaintext

```bash
cat storage/<uuid>.pkg | python3 -m json.tool
# all binary fields are base64-encoded ciphertext — no plaintext visible
```
