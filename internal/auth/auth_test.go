package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kforbus3/container-registry/internal/db"
)

func newTestAuth(t *testing.T) (*Authenticator, *db.DB) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return New(database), database
}

func mustUser(t *testing.T, database *db.DB, name, password, role string) *db.User {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	u, err := database.CreateUser(context.Background(), name, hash, role)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPassword(hash, "correct horse battery") {
		t.Error("correct password rejected")
	}
	if CheckPassword(hash, "wrong password") {
		t.Error("wrong password accepted")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Error("a 5-character password should be rejected")
	}
}

func TestTokenGenerateAndSplit(t *testing.T) {
	plaintext, prefix, hash, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	gotPrefix, secret, ok := SplitToken(plaintext)
	if !ok {
		t.Fatalf("SplitToken rejected a freshly generated token %q", plaintext)
	}
	if gotPrefix != prefix {
		t.Errorf("prefix = %q, want %q", gotPrefix, prefix)
	}
	if hashSecret(secret) != hash {
		t.Error("secret does not hash to the stored value")
	}
	for _, bad := range []string{"", "nope", "crt_short_abc", "xxx_" + prefix + "_" + secret} {
		if _, _, ok := SplitToken(bad); ok {
			t.Errorf("SplitToken(%q) should have failed", bad)
		}
	}
}

func TestAuthenticateToken(t *testing.T) {
	a, database := newTestAuth(t)
	ctx := context.Background()
	u := mustUser(t, database, "ci", "hunter2hunter2", "user")

	plaintext, prefix, hash, _ := GenerateToken()
	if _, err := database.CreateToken(ctx, &db.Token{
		Name: "pipeline", UserID: u.ID, Prefix: prefix, SecretHash: hash,
		CanPull: true, CanPush: true, RepoPattern: "team-a/*",
	}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	p, err := a.AuthenticateToken(ctx, plaintext)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if p.Username != "ci" || !p.CanPush || p.Admin {
		t.Fatalf("unexpected principal %+v", p)
	}
	if _, err := a.AuthenticateToken(ctx, "crt_"+prefix+"_wrongsecret"); err != ErrBadCredentials {
		t.Fatalf("wrong secret: err = %v, want ErrBadCredentials", err)
	}
}

func TestRevokedAndExpiredTokensRejected(t *testing.T) {
	a, database := newTestAuth(t)
	ctx := context.Background()
	u := mustUser(t, database, "ci", "hunter2hunter2", "user")

	// Revoked.
	plaintext, prefix, hash, _ := GenerateToken()
	tok, _ := database.CreateToken(ctx, &db.Token{
		Name: "revoked", UserID: u.ID, Prefix: prefix, SecretHash: hash, CanPull: true, RepoPattern: "*",
	})
	database.RevokeToken(ctx, tok.ID)
	if _, err := a.AuthenticateToken(ctx, plaintext); err != ErrTokenInactive {
		t.Errorf("revoked token: err = %v, want ErrTokenInactive", err)
	}

	// Expired.
	past := time.Now().Add(-time.Hour)
	plaintext2, prefix2, hash2, _ := GenerateToken()
	database.CreateToken(ctx, &db.Token{
		Name: "expired", UserID: u.ID, Prefix: prefix2, SecretHash: hash2,
		CanPull: true, RepoPattern: "*", ExpiresAt: &past,
	})
	if _, err := a.AuthenticateToken(ctx, plaintext2); err != ErrTokenInactive {
		t.Errorf("expired token: err = %v, want ErrTokenInactive", err)
	}
}

func TestDisabledUserBlocksTokens(t *testing.T) {
	a, database := newTestAuth(t)
	ctx := context.Background()
	u := mustUser(t, database, "gone", "hunter2hunter2", "user")

	plaintext, prefix, hash, _ := GenerateToken()
	database.CreateToken(ctx, &db.Token{
		Name: "t", UserID: u.ID, Prefix: prefix, SecretHash: hash, CanPull: true, RepoPattern: "*",
	})
	if err := database.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	if _, err := a.AuthenticateToken(ctx, plaintext); err != ErrDisabled {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
}

func TestAdminTokenCannotExceedItsOwner(t *testing.T) {
	a, database := newTestAuth(t)
	ctx := context.Background()
	// A plain user holding a token flagged is_admin must not become an admin.
	u := mustUser(t, database, "regular", "hunter2hunter2", "user")

	plaintext, prefix, hash, _ := GenerateToken()
	database.CreateToken(ctx, &db.Token{
		Name: "escalate", UserID: u.ID, Prefix: prefix, SecretHash: hash,
		CanPull: true, IsAdmin: true, RepoPattern: "*",
	})
	p, err := a.AuthenticateToken(ctx, plaintext)
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if p.Admin {
		t.Fatal("a non-admin user's token was granted admin rights")
	}
}

func TestScopeMatching(t *testing.T) {
	cases := []struct {
		pattern string
		repo    string
		want    bool
	}{
		{"*", "anything/at/all", true},
		{"", "anything", true},
		{"team-a/*", "team-a/app", true},
		{"team-a/*", "team-a/nested/app", true},
		{"team-a/*", "team-b/app", false},
		{"team-a/*", "team-a", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"team-a/*, shared/base", "shared/base", true},
		{"team-a/*, shared/base", "shared/other", false},
		{"*/app", "team-a/app", true},
		{"app?", "app1", true},
		{"app?", "app12", false},
		{"*-prod", "svc-prod", true},
		{"*-prod", "svc-dev", false},
	}
	for _, c := range cases {
		p := &Principal{RepoPattern: c.pattern, CanPull: true}
		if got := p.CanPullRepo(c.repo); got != c.want {
			t.Errorf("pattern %q vs repo %q = %v, want %v", c.pattern, c.repo, got, c.want)
		}
	}
}

func TestPermissionVerbsAreIndependent(t *testing.T) {
	p := &Principal{CanPull: true, RepoPattern: "*"}
	if !p.CanPullRepo("x") {
		t.Error("pull should be allowed")
	}
	if p.CanPushRepo("x") {
		t.Error("push must not be implied by pull")
	}
	if p.CanDeleteRepo("x") {
		t.Error("delete must not be implied by pull")
	}

	// An admin bypasses both the verb flags and the scope.
	admin := &Principal{Admin: true, RepoPattern: "nothing/matches"}
	if !admin.CanPushRepo("any/repo") || !admin.CanDeleteRepo("any/repo") {
		t.Error("admin should bypass scope and verb restrictions")
	}
}

func TestAuthenticateCredentialAcceptsBothForms(t *testing.T) {
	a, database := newTestAuth(t)
	ctx := context.Background()
	u := mustUser(t, database, "jane", "hunter2hunter2", "user")

	// Password form, as sent by `docker login` with a real password.
	if _, err := a.AuthenticateCredential(ctx, "jane", "hunter2hunter2"); err != nil {
		t.Fatalf("password credential rejected: %v", err)
	}
	// Token form, as sent by `docker login` with a token as the password.
	plaintext, prefix, hash, _ := GenerateToken()
	database.CreateToken(ctx, &db.Token{
		Name: "t", UserID: u.ID, Prefix: prefix, SecretHash: hash, CanPull: true, RepoPattern: "*",
	})
	if _, err := a.AuthenticateCredential(ctx, "jane", plaintext); err != nil {
		t.Fatalf("token credential rejected: %v", err)
	}
	// The username is ignored when a token is presented, so the placeholder
	// names clients conventionally use all work.
	for _, name := range []string{"token", "ci-bot", "someone-else", ""} {
		p, err := a.AuthenticateCredential(ctx, name, plaintext)
		if err != nil {
			t.Fatalf("token rejected under username %q: %v", name, err)
		}
		// The principal always resolves to the token's real owner, never to
		// whatever name the client supplied.
		if p.Username != "jane" {
			t.Fatalf("username %q resolved to principal %q, want jane", name, p.Username)
		}
	}

	// A wrong password must still fail, whatever the username.
	if _, err := a.AuthenticateCredential(ctx, "jane", "not-the-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
}
