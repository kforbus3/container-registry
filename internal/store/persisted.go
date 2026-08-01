package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Storage configuration that an operator can change without editing the
// environment and restarting.
//
// The environment still wins where it is set. Somebody who configured
// REGISTRY_S3_BUCKET in a unit file or a compose file expects that to be the
// answer, and a value quietly overridden from a web form is a bad surprise
// during an incident. So the UI edits this only when the environment is silent
// about it, and says so when it is not.

// PersistedConfig is a storage backend described well enough to rebuild it.
// The secret key is held separately so it is never serialised with the rest.
type PersistedConfig struct {
	Kind string `json:"kind"` // "filesystem" or "s3"

	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	PathStyle bool   `json:"path_style,omitempty"`

	// SecretKey is encrypted at rest; see SealSecret.
	SealedSecret string `json:"sealed_secret,omitempty"`
}

// S3 turns a persisted configuration into an S3Config, decrypting the secret.
func (c PersistedConfig) S3(key []byte) (S3Config, error) {
	secret, err := OpenSecret(key, c.SealedSecret)
	if err != nil {
		return S3Config{}, err
	}
	return S3Config{
		Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket,
		Prefix: c.Prefix, AccessKey: c.AccessKey, SecretKey: secret,
		PathStyle: c.PathStyle,
	}, nil
}

// FromS3 records an S3Config for persistence, sealing the secret.
func FromS3(cfg S3Config, key []byte) (PersistedConfig, error) {
	sealed, err := SealSecret(key, cfg.SecretKey)
	if err != nil {
		return PersistedConfig{}, err
	}
	return PersistedConfig{
		Kind: "s3", Endpoint: cfg.Endpoint, Region: cfg.Region,
		Bucket: cfg.Bucket, Prefix: cfg.Prefix, AccessKey: cfg.AccessKey,
		PathStyle: cfg.PathStyle, SealedSecret: sealed,
	}, nil
}

func (c PersistedConfig) Marshal() (string, error) {
	b, err := json.Marshal(c)
	return string(b), err
}

func ParsePersisted(s string) (PersistedConfig, bool) {
	if s == "" {
		return PersistedConfig{}, false
	}
	var c PersistedConfig
	if err := json.Unmarshal([]byte(s), &c); err != nil || c.Kind == "" {
		return PersistedConfig{}, false
	}
	return c, true
}

// ---------------------------------------------------------------- secrets

// ConfigKey loads, or creates, the key used to encrypt stored credentials.
//
// It lives in a file beside the database rather than inside it. An object-store
// secret and the metadata it protects should not both fall out of a single
// stolen SQLite file, and a backup of the database alone is the most likely way
// for that file to travel.
func ConfigKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "config.key")
	b, err := os.ReadFile(path)
	if err == nil {
		key, decErr := base64.StdEncoding.DecodeString(string(b))
		if decErr == nil && len(key) == 32 {
			return key, nil
		}
		return nil, fmt.Errorf("%s is not a valid key; move it aside to regenerate", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(path, []byte(enc), 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", path, err)
	}
	return key, nil
}

// SealSecret encrypts a credential with AES-GCM. An empty secret seals to an
// empty string rather than to ciphertext, so "not set" stays distinguishable.
func SealSecret(key []byte, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(secret), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// OpenSecret reverses SealSecret.
func OpenSecret(key []byte, sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("stored credential is not valid base64")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("stored credential is truncated")
	}
	out, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("stored credential could not be decrypted; " +
			"config.key may not be the one it was saved with")
	}
	return string(out), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	sum := sha256.Sum256(append([]byte("registry-storage-config-v1|"), key...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
