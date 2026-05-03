package crypto_test

import (
	"testing"

	"whisper/internal/crypto"
)

func TestPackUnpack(t *testing.T) {
	senderPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	recipientPriv, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("top secret file contents")
	pkg, err := crypto.Pack(plaintext, "secret.txt", "sender-id", "recipient-id", senderPriv, &recipientPriv.PublicKey)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	got, err := crypto.Unpack(pkg, &senderPriv.PublicKey, recipientPriv)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

func TestUnpackRejectsWrongSender(t *testing.T) {
	senderPriv, _ := crypto.GenerateKeyPair()
	recipientPriv, _ := crypto.GenerateKeyPair()
	attacker, _ := crypto.GenerateKeyPair()

	pkg, err := crypto.Pack([]byte("data"), "f.txt", "s", "r", senderPriv, &recipientPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with attacker's key should fail.
	_, err = crypto.Unpack(pkg, &attacker.PublicKey, recipientPriv)
	if err == nil {
		t.Fatal("expected signature verification to fail with wrong public key")
	}
}

func TestUnpackRejectsTamperedCiphertext(t *testing.T) {
	senderPriv, _ := crypto.GenerateKeyPair()
	recipientPriv, _ := crypto.GenerateKeyPair()

	pkg, err := crypto.Pack([]byte("data"), "f.txt", "s", "r", senderPriv, &recipientPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext.
	pkg.Ciphertext = "AAAA" + pkg.Ciphertext[4:]

	_, err = crypto.Unpack(pkg, &senderPriv.PublicKey, recipientPriv)
	if err == nil {
		t.Fatal("expected verification to fail after ciphertext tampering")
	}
}
