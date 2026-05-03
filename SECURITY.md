# Security Design — Whisper

This document explains, in detail, every cryptographic operation the system performs, what each primitive guarantees, and how the composition of those primitives achieves the four core security properties: **confidentiality**, **integrity**, **authentication**, and **non-repudiation**.

---

## 1. Primitives and Why They Were Chosen

### AES-256-GCM (file encryption)

AES-GCM is an authenticated encryption with associated data (AEAD) scheme. It provides two guarantees in a single operation:

- **Confidentiality** — the ciphertext reveals nothing about the plaintext without the key.
- **Ciphertext integrity** — any modification to the ciphertext (even a single bit flip) causes decryption to fail with an explicit error. This is enforced by a 128-bit authentication tag that GCM appends to the ciphertext.

The key is 256 bits (32 bytes), generated fresh from a cryptographically secure random source (`crypto/rand`) for every single transfer. Because the key is never reused, breaking one transfer does not weaken any other.

The nonce is 12 bytes, also randomly generated per transfer. GCM is correct and secure as long as (key, nonce) pairs are never reused. Since both are freshly generated for each transfer, this is trivially satisfied.

### RSA-2048 key pairs (per user)

Each user generates one RSA key pair locally, before they ever contact the server. The private key never leaves the user's machine. The public key is uploaded to the server so that senders can retrieve it.

RSA-2048 provides a security level of approximately 112 bits, which is the current NIST recommendation for long-term keys. For a higher security margin, the key size can be increased to 4096 bits with no protocol changes.

### RSA-OAEP with SHA-256 (key encapsulation)

Optimal Asymmetric Encryption Padding (OAEP) is a probabilistic padding scheme that makes RSA encryption semantically secure (IND-CCA2). This means:

- Two encryptions of the same plaintext produce different ciphertexts (probabilistic due to random padding).
- An attacker who can query a decryption oracle cannot recover the plaintext.

OAEP is used here exclusively to encrypt the 32-byte AES key, not the file itself. Asymmetric encryption of large data directly with RSA is slow and has message-size limits. The hybrid approach (RSA wraps the AES key; AES encrypts the file) is the standard solution.

### RSA-PSS with SHA-256 (digital signatures)

Probabilistic Signature Scheme (PSS) is the modern, provably secure RSA signing mode. It is preferred over PKCS#1 v1.5 because:

- Its security is tightly reducible to the hardness of RSA.
- It is not vulnerable to the Bleichenbacher padding-oracle attacks that affect PKCS#1 v1.5 signatures in some implementations.

The message is first hashed with SHA-256 (producing a 32-byte digest), and the signature is computed over that digest. The signature proves that the signer held the corresponding private key at the time of signing, and that the signed data has not been altered since.

### Argon2id (password hashing)

Argon2id is the winner of the Password Hashing Competition (2015) and the current NIST recommendation. It is memory-hard, meaning that brute-force attacks require significant RAM, which raises the cost of large-scale offline cracking.

Parameters used: `m=65536` (64 MiB), `t=3` (3 iterations), `p=2` (2 threads). These are consistent with OWASP recommendations for interactive logins.

A fresh 16-byte random salt is generated per password. The output is stored in PHC string format (`$argon2id$...`) so the parameters are self-describing and can be upgraded in the future without breaking existing hashes.

---

## 2. The Full Send Flow, Step by Step

### Step 1 — Sender authenticates

The sender POSTs their username and password to `/auth/login`. The server:

1. Fetches the stored Argon2id hash for that username.
2. Recomputes Argon2id with the submitted password and the stored salt.
3. Compares the result with the stored hash using a constant-time comparison (`crypto/subtle.ConstantTimeCompare`) to prevent timing attacks.
4. If they match, issues a JWT signed with HMAC-SHA-256.

The JWT contains the user's UUID (`sub`) and username, an issued-at timestamp (`iat`), and an expiry (`exp`, 24 hours). Every subsequent authenticated request carries this token in the `Authorization: Bearer` header.

### Step 2 — Sender fetches the recipient's public key

The sender calls `GET /api/v1/keys/{recipient_username}`. The server returns:

```json
{
  "user_id":    "<recipient UUID>",
  "username":   "bob",
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

This endpoint requires no authentication because public keys are, by definition, public. The sender now has the recipient's RSA public key and UUID.

**Trust assumption:** The server is trusted to return the correct public key for a given username. In a production system, a certificate authority or key-signing ceremony would be needed to prevent a compromised server from substituting its own key. For this prototype the server is assumed honest-but-curious: it may read stored data but will not actively substitute keys.

### Step 3 — Sender builds the encrypted package

This is the core of the protocol. All of the following happens entirely on the sender's machine, in memory, before anything is sent to the server.

#### 3a. Generate a fresh AES-256 key

```
aes_key ← crypto/rand (32 bytes)
```

#### 3b. Generate a fresh nonce

```
nonce ← crypto/rand (12 bytes)
```

#### 3c. Encrypt the file

```
ciphertext || tag ← AES-256-GCM.Encrypt(key=aes_key, nonce=nonce, plaintext=file_bytes)
```

GCM appends the 128-bit authentication tag to the ciphertext. The combined value stored in `ciphertext` is `enc_bytes || tag`. On decryption, GCM verifies the tag before returning any plaintext, so a tampered ciphertext causes a hard failure.

#### 3d. Wrap the AES key for the recipient

```
encrypted_key ← RSA-OAEP.Encrypt(key=recipient_pub, plaintext=aes_key)
```

After this step, `aes_key` exists only in the sender's memory. The server will never see it. The only party who can recover it is the holder of `recipient_priv`.

#### 3e. Assemble the package (signature pending)

```json
{
  "sender_id":     "<sender UUID>",
  "recipient_id":  "<recipient UUID>",
  "filename":      "secret.txt",
  "timestamp":     1714900000,
  "encrypted_key": "<base64(encrypted_key)>",
  "nonce":         "<base64(nonce)>",
  "ciphertext":    "<base64(ciphertext || tag)>",
  "signature":     ""
}
```

#### 3f. Sign the package

The package is serialised to JSON with `signature` set to the empty string. This canonical serialisation is the exact byte string that will be hashed and signed:

```
signable_bytes ← JSON.Marshal(package with signature="")
digest         ← SHA-256(signable_bytes)
signature      ← RSA-PSS.Sign(key=sender_priv, message=digest)
```

The final `signature` field is set to `base64(signature)`.

**Why sign the whole package and not just the ciphertext?**
The signature covers `sender_id`, `recipient_id`, `filename`, `timestamp`, `encrypted_key`, `nonce`, and `ciphertext`. If only the ciphertext were signed:

- An attacker could re-address the package to a different recipient by replacing `recipient_id` and re-wrapping `encrypted_key` with a different public key — the signature would still verify.
- An attacker could change the `filename` field to mislead the recipient.

Signing all fields prevents these attacks.

### Step 4 — Upload to server

The sender POSTs the complete package JSON to `/api/v1/transfers`.

The server performs the following checks **before** storing anything:

1. **JWT validation** — extracts the sender's UUID from the token.
2. **Sender identity check** — asserts that `package.sender_id == jwt.sub`. A user cannot upload a package claiming to be from someone else.
3. **Recipient existence check** — queries the database to confirm `package.recipient_id` belongs to a real user.
4. **Signature verification** — fetches the sender's registered public key from the database, recomputes `SHA-256(signable_bytes)`, and calls `RSA-PSS.Verify`. If the signature does not verify, the upload is rejected with HTTP 400.

If all checks pass, the server:

- Assigns a UUID to the transfer.
- Writes the package JSON to disk at `storage/<uuid>.pkg` (mode 0600).
- Inserts a metadata row into the `transfers` table (sender, recipient, filename, file path, timestamp). **No plaintext or key material is stored in the database.**

---

## 3. The Full Receive Flow, Step by Step

### Step 1 — List inbox

The recipient calls `GET /api/v1/transfers`. The server returns only transfers where `recipient_id` matches the JWT subject. Each entry contains the transfer ID, sender ID, filename, and timestamp — all metadata, no ciphertext.

### Step 2 — Download the package

The recipient calls `GET /api/v1/transfers/{id}`. The server checks that `transfer.recipient_id == jwt.sub` before returning the package. A different authenticated user calling this endpoint receives HTTP 403.

### Step 3 — Verify the signature (client-side)

The recipient's client:

1. Fetches the sender's public key from `GET /api/v1/keys/id/{sender_id}`.
2. Sets `package.signature` aside, zeroes it in a copy, serialises the copy to JSON.
3. Computes `SHA-256(signable_bytes)`.
4. Calls `RSA-PSS.Verify(key=sender_pub, digest=hash, sig=decoded_signature)`.

If this fails, the client aborts and reports an error. The signature was already verified server-side on upload, but the client verifies again because:

- The server is honest-but-curious and could have modified the stored package after upload.
- End-to-end security requires that the recipient independently confirms the sender's identity without trusting the server.

### Step 4 — Decrypt the AES key

```
aes_key ← RSA-OAEP.Decrypt(key=recipient_priv, ciphertext=decoded(encrypted_key))
```

This operation can only succeed on the recipient's machine because `recipient_priv` never left it.

### Step 5 — Decrypt the file

```
plaintext ← AES-256-GCM.Decrypt(key=aes_key, nonce=decoded(nonce), ciphertext=decoded(ciphertext))
```

GCM internally verifies the authentication tag as part of decryption. If the ciphertext was tampered with (even one bit) after the sender signed the package, GCM will reject it here even if the RSA signature somehow passed.

This gives two independent layers of integrity checking:
- **RSA-PSS** catches modifications to any field in the package (metadata, encrypted key, nonce, ciphertext).
- **AES-GCM tag** catches modifications to the raw ciphertext bytes specifically.

---

## 4. Security Properties, Formally Stated

### Confidentiality

The file bytes are protected by AES-256-GCM. The AES key is protected by RSA-OAEP under the recipient's public key. The only party who can decrypt is the holder of `recipient_priv`. The server stores only ciphertext. Even if the server's database and storage directory are fully compromised, no plaintext is recoverable without the recipient's private key.

### Integrity

AES-GCM appends a 128-bit authentication tag computed over the ciphertext using the AES key. Any modification to the ciphertext after encryption will cause tag verification to fail at decryption time. The tag is not stored separately — it is appended to the ciphertext field — so there is no way to strip or replace it without the AES key.

### Authentication

The RSA-PSS signature, verified against the sender's registered public key, proves that the package was created by someone who holds `sender_priv`. Registration ties `sender_priv` to a specific username. Therefore, a successfully verified signature means the package was created by the account named in `sender_id`. A forged signature would require breaking RSA-2048.

### Non-repudiation

Because `sender_priv` never leaves the sender's machine, only the sender could have produced a valid signature. The sender cannot later claim the package came from someone else. The signed fields include `sender_id`, `recipient_id`, `filename`, and `timestamp`, providing a timestamped record of intent.

### Protection Against Specific Attacks

| Attack | Prevented by |
|---|---|
| Server reads stored files | AES-256-GCM encryption; server lacks `recipient_priv` |
| Network eavesdropper reads traffic | Ciphertext is already encrypted before upload |
| Attacker replaces ciphertext on disk | AES-GCM tag fails; RSA-PSS signature also fails |
| Attacker re-addresses package to self | RSA-PSS signature covers `recipient_id`; verification fails |
| Attacker impersonates sender | RSA-PSS verification requires `sender_priv` |
| Attacker replays an old package | `timestamp` field is signed; recipient can check freshness |
| Offline password crack | Argon2id memory-hardness; unique per-user salt |
| JWT forgery | HMAC-SHA-256 under server-side `JWT_SECRET` |
| Timing attack on password check | `crypto/subtle.ConstantTimeCompare` |

---

## 5. What the Server Knows

Because the server is assumed honest-but-curious, it is worth being explicit about what it can and cannot observe.

**Can observe:**
- Who registered (usernames, Argon2id hashes — not passwords).
- Who sent a file to whom, when, and under what filename (transfer metadata).
- The encrypted package bytes (ciphertext, wrapped key, nonce, signature).
- Which public keys are registered.

**Cannot observe:**
- Plaintext file contents (protected by AES-256-GCM).
- The AES key (protected by RSA-OAEP under recipient's public key).
- The sender's or recipient's private keys (never transmitted).
- User passwords (only Argon2id hashes are stored).

**Cannot forge:**
- A valid package signature (requires `sender_priv`).
- A JWT for a user it has not issued one to (requires `JWT_SECRET`, which it already knows — this is a server-side secret).

The server learns the social graph (who communicates with whom) and filenames. Hiding this metadata would require additional techniques (e.g., private information retrieval, onion routing) which are out of scope for this prototype.

---

## 6. Key Management

### Private key storage

Private keys are written to `~/.config/whisper/keys/private.pem` with permissions `0600` (owner read/write only). No passphrase protects the key file in this prototype. In a production system, the private key would be encrypted at rest using a key derived from the user's password (e.g., PBKDF2 or Argon2id), so that theft of the key file alone is insufficient.

### Key rotation

The `PUT /api/v1/keys` endpoint upserts the public key — calling it again replaces the old key. Any packages encrypted under the old key remain decryptable only with the old private key. There is no automatic re-encryption of existing packages on key rotation. This is a known limitation of the prototype.

### Trust on first use

When a sender fetches a recipient's public key for the first time, they have no way to verify it is authentic beyond trusting the server. This is the "trust on first use" (TOFU) model, the same model used by SSH. A production system would require out-of-band key verification (e.g., key fingerprint comparison) or a PKI.
