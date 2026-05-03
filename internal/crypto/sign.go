package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Sign returns an RSA-PSS signature over SHA-256(message).
func Sign(priv *rsa.PrivateKey, message []byte) ([]byte, error) {
	h := sha256.Sum256(message)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], nil)
}

// Verify checks an RSA-PSS signature over SHA-256(message).
func Verify(pub *rsa.PublicKey, message, sig []byte) error {
	h := sha256.Sum256(message)
	return rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, nil)
}
