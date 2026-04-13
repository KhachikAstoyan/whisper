package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"

	"whisper/internal/models"
	"whisper/internal/repository"
)

const (
	argon2Memory  = 64 * 1024
	argon2Time    = 3
	argon2Threads = 2
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

var (
	ErrUserExists   = errors.New("username already taken")
	ErrInvalidCreds = errors.New("invalid username or password")
	ErrInvalidToken = errors.New("invalid or expired token")
)

type AuthService struct {
	users     *repository.UserRepo
	jwtSecret []byte
}

func NewAuthService(users *repository.UserRepo, jwtSecret string) *AuthService {
	return &AuthService{
		users:     users,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *AuthService) Register(ctx context.Context, username, password string) (*models.User, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	user, err := s.users.Create(ctx, username, hash)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return nil, ErrUserExists
		}
		return nil, err
	}
	return user, nil
}

func (s *AuthService) Login(ctx context.Context, username, password string) (string, *models.User, error) {
	user, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", nil, ErrInvalidCreds
		}
		return "", nil, err
	}
	if err := verifyPassword(password, user.PasswordHash); err != nil {
		return "", nil, ErrInvalidCreds
	}
	token, err := s.issueToken(user)
	if err != nil {
		return "", nil, err
	}
	return token, user, nil
}

func (s *AuthService) ValidateToken(tokenStr string) (*models.User, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	sub, _ := claims["sub"].(string)
	username, _ := claims["username"].(string)
	if sub == "" || username == "" {
		return nil, ErrInvalidToken
	}
	return &models.User{ID: sub, Username: username}, nil
}

func (s *AuthService) issueToken(user *models.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"iat":      now.Unix(),
		"exp":      now.Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// hashPassword returns a PHC-format Argon2id string:
// $argon2id$v=<v>$m=<m>,t=<t>,p=<p>$<salt_b64>$<hash_b64>
func hashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// verifyPassword checks a plaintext password against a PHC-format Argon2id hash.
func verifyPassword(password, encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("invalid hash format")
	}
	var memory, t uint32
	var threads uint8
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &t, &threads)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return err
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return err
	}

	computed := argon2.IDKey([]byte(password), salt, t, memory, threads, uint32(len(expected)))
	if subtle.ConstantTimeCompare(computed, expected) != 1 {
		return errors.New("password mismatch")
	}
	return nil
}
