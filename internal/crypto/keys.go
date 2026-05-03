package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

const rsaBits = 2048

func GenerateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaBits)
}

func MarshalPrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func MarshalPublicKey(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func ParsePublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rsaPub, nil
}

func SaveKeyPair(dir string, priv *rsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	privPEM := MarshalPrivateKey(priv)
	if err := os.WriteFile(filepath.Join(dir, "private.pem"), privPEM, 0600); err != nil {
		return err
	}
	pubPEM, err := MarshalPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "public.pem"), pubPEM, 0644)
}

func LoadPrivateKey(dir string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Join(dir, "private.pem"))
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(data)
}

func LoadPublicKeyPEM(dir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, "public.pem"))
}
