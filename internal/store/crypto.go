package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Sealer encrypts failure-report content at rest.
//
// Failure reports are the one format that carries recipient addresses and
// message content, and the daemon refuses to write that in the clear. AES-256-
// GCM with a random nonce per blob is enough: the threat is the database file
// leaving the machine — backups, copied disks — not an online adversary.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a sealer from a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("failure key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// NewSealerFromFile reads a hex-encoded 32-byte key. Hex, because a raw binary
// key file cannot be pasted into sops or generated with openssl rand -hex.
func NewSealerFromFile(path string) (*Sealer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read failure key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("failure key is not hex: %w", err)
	}
	s, err := NewSealer(key)
	if err != nil {
		return nil, fmt.Errorf("failure key %s: %w", path, err)
	}
	return s, nil
}

// Seal encrypts plain into a self-contained blob: nonce followed by ciphertext.
func (s *Sealer) Seal(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, nil), nil
}

// Open decrypts a blob produced by Seal.
func (s *Sealer) Open(blob []byte) ([]byte, error) {
	if len(blob) < s.aead.NonceSize() {
		return nil, fmt.Errorf("sealed blob is truncated")
	}
	nonce, ct := blob[:s.aead.NonceSize()], blob[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failure content: %w", err)
	}
	return plain, nil
}
