package crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// EncryptedPackage is the on-wire and on-disk format for a secure file transfer.
// All binary fields are base64-encoded. The Signature covers all other fields.
type EncryptedPackage struct {
	SenderID     string `json:"sender_id"`
	RecipientID  string `json:"recipient_id"`
	Filename     string `json:"filename"`
	Timestamp    int64  `json:"timestamp"`
	EncryptedKey string `json:"encrypted_key"` // base64(RSA-OAEP(aesKey, recipientPub))
	Nonce        string `json:"nonce"`         // base64(AES-GCM nonce)
	Ciphertext   string `json:"ciphertext"`    // base64(AES-GCM ciphertext)
	Signature    string `json:"signature"`     // base64(RSA-PSS sig over the above fields)
}

// SignableBytes serialises the package with Signature zeroed, producing the
// canonical byte string that is hashed and signed/verified.
func SignableBytes(pkg *EncryptedPackage) ([]byte, error) {
	tmp := *pkg
	tmp.Signature = ""
	return json.Marshal(tmp)
}

// Pack encrypts plaintext for recipientPub and signs the package with senderPriv.
func Pack(
	plaintext []byte,
	filename, senderID, recipientID string,
	senderPriv *rsa.PrivateKey,
	recipientPub *rsa.PublicKey,
) (*EncryptedPackage, error) {
	aesKey, err := GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("generate aes key: %w", err)
	}
	nonce, ciphertext, err := AESEncrypt(aesKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("aes encrypt: %w", err)
	}
	wrappedKey, err := WrapKey(recipientPub, aesKey)
	if err != nil {
		return nil, fmt.Errorf("wrap key: %w", err)
	}

	pkg := &EncryptedPackage{
		SenderID:     senderID,
		RecipientID:  recipientID,
		Filename:     filename,
		Timestamp:    time.Now().Unix(),
		EncryptedKey: base64.StdEncoding.EncodeToString(wrappedKey),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}

	signable, err := SignableBytes(pkg)
	if err != nil {
		return nil, fmt.Errorf("marshal for signing: %w", err)
	}
	sig, err := Sign(senderPriv, signable)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	pkg.Signature = base64.StdEncoding.EncodeToString(sig)
	return pkg, nil
}

// Unpack verifies the package signature with senderPub, decrypts the AES key
// with recipientPriv, and returns the original plaintext.
func Unpack(
	pkg *EncryptedPackage,
	senderPub *rsa.PublicKey,
	recipientPriv *rsa.PrivateKey,
) ([]byte, error) {
	sig, err := base64.StdEncoding.DecodeString(pkg.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	signable, err := SignableBytes(pkg)
	if err != nil {
		return nil, fmt.Errorf("marshal for verify: %w", err)
	}
	if err := Verify(senderPub, signable, sig); err != nil {
		return nil, fmt.Errorf("signature invalid: %w", err)
	}

	wrappedKey, err := base64.StdEncoding.DecodeString(pkg.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted key: %w", err)
	}
	aesKey, err := UnwrapKey(recipientPriv, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(pkg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(pkg.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	return AESDecrypt(aesKey, nonce, ct)
}
