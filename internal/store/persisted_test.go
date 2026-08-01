package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSealRoundTripAndTamper(t *testing.T) {
	key, err := ConfigKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealSecret(key, "s3-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if sealed == "" || sealed == "s3-secret-value" {
		t.Fatal("the secret was not actually sealed")
	}
	got, err := OpenSecret(key, sealed)
	if err != nil || got != "s3-secret-value" {
		t.Fatalf("round trip gave %q, %v", got, err)
	}

	// A different key must not open it: that is the whole point of keeping the
	// key out of the database.
	other, _ := ConfigKey(t.TempDir())
	if _, err := OpenSecret(other, sealed); err == nil {
		t.Error("a foreign key opened the credential")
	}

	// An empty secret stays empty rather than becoming ciphertext, so "unset"
	// remains distinguishable from "set to empty".
	if s, _ := SealSecret(key, ""); s != "" {
		t.Errorf("empty secret sealed to %q", s)
	}
}

func TestConfigKeyIsStableAndPrivate(t *testing.T) {
	dir := t.TempDir()
	a, err := ConfigKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ConfigKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("ConfigKey regenerated instead of reusing the stored key")
	}
	info, err := os.Stat(filepath.Join(dir, "config.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config.key mode is %04o, want 0600", perm)
	}
}

func TestPersistedNeverCarriesPlaintextSecret(t *testing.T) {
	key, _ := ConfigKey(t.TempDir())
	cfg := S3Config{Bucket: "b", AccessKey: "AKIA", SecretKey: "top-secret-value"}
	p, err := FromS3(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if contains(blob, "top-secret-value") {
		t.Fatal("the serialised configuration contains the secret in clear")
	}
	back, ok := ParsePersisted(blob)
	if !ok {
		t.Fatal("could not parse what we just marshalled")
	}
	got, err := back.S3(key)
	if err != nil {
		t.Fatal(err)
	}
	if got.SecretKey != "top-secret-value" || got.Bucket != "b" {
		t.Errorf("round trip lost data: %+v", got)
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
