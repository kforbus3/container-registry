// Package auth handles credentials: user passwords, API tokens, web sessions,
// and the permission model applied to repositories.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kforbus3/container-registry/internal/db"
)

var (
	ErrBadCredentials = errors.New("invalid credentials")
	ErrDisabled       = errors.New("account disabled")
	ErrTokenInactive  = errors.New("token revoked or expired")
)

// TokenPrefixLen is the number of hex characters used as the lookup key of a
// token. It is stored in clear so a token can be identified without a scan.
const TokenPrefixLen = 12

// tokenLabel prefixes every issued token so leaked credentials are greppable.
const tokenLabel = "crt"

// ---------------------------------------------------------------- passwords

func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	if len(pw) > 72 {
		// bcrypt silently truncates beyond 72 bytes; reject rather than mislead.
		return "", errors.New("password must be at most 72 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// ---------------------------------------------------------------- tokens

// NewSecret returns a URL-safe random string with n bytes of entropy.
func NewSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateToken produces a token of the form crt_<prefix>_<secret> along with
// the prefix and the hash to persist. The plaintext is shown to the user once.
func GenerateToken() (plaintext, prefix, secretHash string, err error) {
	pb := make([]byte, TokenPrefixLen/2)
	if _, err = rand.Read(pb); err != nil {
		return "", "", "", err
	}
	prefix = hex.EncodeToString(pb)
	secret, err := NewSecret(32)
	if err != nil {
		return "", "", "", err
	}
	plaintext = fmt.Sprintf("%s_%s_%s", tokenLabel, prefix, secret)
	secretHash = hashSecret(secret)
	return plaintext, prefix, secretHash, nil
}

// hashSecret uses SHA-256 rather than bcrypt: the secret already carries 256
// bits of entropy, so stretching buys nothing and would cost a bcrypt round on
// every blob upload request.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SplitToken parses a token plaintext into its prefix and secret parts.
//
// The secret is base64url, whose alphabet includes '_', so the split must be
// bounded at three parts — otherwise every token containing an underscore in
// its secret would be rejected.
func SplitToken(tok string) (prefix, secret string, ok bool) {
	parts := strings.SplitN(tok, "_", 3)
	if len(parts) != 3 || parts[0] != tokenLabel || len(parts[1]) != TokenPrefixLen || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// ---------------------------------------------------------------- principal

// Principal is an authenticated caller: either a user (web session or password
// login) or an API token acting on a user's behalf.
type Principal struct {
	UserID   int64
	Username string
	// TokenID is zero for password/session logins.
	TokenID   int64
	TokenName string

	Admin       bool
	CanPull     bool
	CanPush     bool
	CanDelete   bool
	RepoPattern string

	// Scopes, when non-nil, are the access grants carried by a bearer token
	// issued by this registry. They replace the pattern entirely: the token
	// says exactly what it may do, and nothing outside that list is permitted.
	Scopes []string

	// Bearer marks a principal that came from a token this registry issued
	// through the Docker token flow. Such a token is a credential for the
	// distribution API and nothing else, so the management API refuses it.
	Bearer bool
}

// scopeGrants reports whether the principal's bearer-token scopes permit an
// action on a repository. It is only consulted when Scopes is non-nil.
func (p *Principal) scopeGrants(repo, action string) bool {
	want := "repository:" + repo + ":"
	for _, s := range p.Scopes {
		if !strings.HasPrefix(s, want) {
			continue
		}
		for _, a := range strings.Split(strings.TrimPrefix(s, want), ",") {
			if a == action {
				return true
			}
		}
	}
	return false
}

// Anonymous is the zero principal used when anonymous pull is enabled.
func Anonymous() *Principal {
	return &Principal{Username: "anonymous", CanPull: true, RepoPattern: "*"}
}

func (p *Principal) IsAnonymous() bool { return p != nil && p.UserID == 0 && p.TokenID == 0 }

// Display renders the actor for audit entries.
func (p *Principal) Display() string {
	if p == nil {
		return "anonymous"
	}
	if p.TokenName != "" {
		return fmt.Sprintf("%s (token:%s)", p.Username, p.TokenName)
	}
	return p.Username
}

// scopeAllows reports whether the principal's repo pattern covers repo.
// Patterns are comma-separated globs where * matches any run of characters,
// including slashes: "team-a/*, shared/base".
func (p *Principal) scopeAllows(repo string) bool {
	if p == nil {
		return false
	}
	pattern := strings.TrimSpace(p.RepoPattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	for _, pat := range strings.Split(pattern, ",") {
		if matchGlob(strings.TrimSpace(pat), repo) {
			return true
		}
	}
	return false
}

// CanPullRepo, CanPushRepo and CanDeleteRepo combine the verb permission with
// the repository scope. Admin principals bypass both.
func (p *Principal) CanPullRepo(repo string) bool {
	if p == nil {
		return false
	}
	if p.Scopes != nil {
		return p.scopeGrants(repo, "pull")
	}
	return p.Admin || (p.CanPull && p.scopeAllows(repo))
}

func (p *Principal) CanPushRepo(repo string) bool {
	if p == nil {
		return false
	}
	if p.Scopes != nil {
		return p.scopeGrants(repo, "push")
	}
	return p.Admin || (p.CanPush && p.scopeAllows(repo))
}

func (p *Principal) CanDeleteRepo(repo string) bool {
	if p == nil {
		return false
	}
	if p.Scopes != nil {
		return p.scopeGrants(repo, "delete")
	}
	return p.Admin || (p.CanDelete && p.scopeAllows(repo))
}

// matchGlob matches pattern against s, where '*' matches any sequence of
// characters (including '/') and '?' matches exactly one character.
func matchGlob(pattern, s string) bool {
	// Iterative backtracking match: linear in the common case, and unlike a
	// recursive version it cannot blow the stack on pathological patterns.
	var pi, si, starIdx, matchIdx = 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			starIdx = pi
			matchIdx = si
			pi++
		case starIdx != -1:
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// ---------------------------------------------------------------- resolution

type Authenticator struct {
	DB *db.DB

	// touchMu guards lastTouch, which throttles last_used_at writes. Without
	// it every blob GET on a busy pull would issue a database write.
	touchMu   sync.Mutex
	lastTouch map[int64]time.Time

	// validMu guards lastValid, the cache behind StillValid.
	validMu   sync.Mutex
	lastValid map[validityKey]time.Time
}

// touchInterval is how stale a token's last_used_at may get before it is
// rewritten. It trades exactness for a bounded write rate.
const touchInterval = time.Minute

func New(database *db.DB) *Authenticator {
	return &Authenticator{
		DB:        database,
		lastTouch: map[int64]time.Time{},
		lastValid: map[validityKey]time.Time{},
	}
}

// noteTokenUse records that a token was used, at most once per touchInterval.
// It runs inline: a background goroutine could outlive the request and write
// to a database that is already closing.
func (a *Authenticator) noteTokenUse(ctx context.Context, tokenID int64) {
	now := time.Now()
	a.touchMu.Lock()
	if last, ok := a.lastTouch[tokenID]; ok && now.Sub(last) < touchInterval {
		a.touchMu.Unlock()
		return
	}
	a.lastTouch[tokenID] = now
	a.touchMu.Unlock()

	a.DB.TouchToken(ctx, tokenID)
}

// principalForUser builds a full-rights principal for a user account.
func principalForUser(u *db.User) *Principal {
	return &Principal{
		UserID:      u.ID,
		Username:    u.Username,
		Admin:       u.IsAdmin(),
		CanPull:     true,
		CanPush:     true,
		CanDelete:   true,
		RepoPattern: "*",
	}
}

// AuthenticatePassword verifies a username/password pair.
func (a *Authenticator) AuthenticatePassword(ctx context.Context, username, password string) (*Principal, error) {
	u, err := a.DB.GetUserByName(ctx, username)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// Spend a comparable amount of time so a missing user and a wrong
			// password are not distinguishable by response latency.
			bcrypt.CompareHashAndPassword([]byte("$2a$10$"+strings.Repeat("x", 53)), []byte(password))
			return nil, ErrBadCredentials
		}
		return nil, err
	}
	if !CheckPassword(u.PasswordHash, password) {
		return nil, ErrBadCredentials
	}
	if u.Disabled {
		return nil, ErrDisabled
	}
	return principalForUser(u), nil
}

// AuthenticateToken verifies an API token plaintext.
func (a *Authenticator) AuthenticateToken(ctx context.Context, plaintext string) (*Principal, error) {
	prefix, secret, ok := SplitToken(plaintext)
	if !ok {
		return nil, ErrBadCredentials
	}
	t, err := a.DB.GetTokenByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrBadCredentials
		}
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(t.SecretHash), []byte(hashSecret(secret))) != 1 {
		return nil, ErrBadCredentials
	}
	if !t.Active() {
		return nil, ErrTokenInactive
	}
	u, err := a.DB.GetUser(ctx, t.UserID)
	if err != nil {
		return nil, ErrBadCredentials
	}
	if u.Disabled {
		return nil, ErrDisabled
	}
	a.noteTokenUse(ctx, t.ID)

	// A token can never exceed the rights of the user that owns it.
	return &Principal{
		UserID:      u.ID,
		Username:    u.Username,
		TokenID:     t.ID,
		TokenName:   t.Name,
		Admin:       t.IsAdmin && u.IsAdmin(),
		CanPull:     t.CanPull,
		CanPush:     t.CanPush,
		CanDelete:   t.CanDelete,
		RepoPattern: t.RepoPattern,
	}, nil
}

// AuthenticateCredential accepts either a token plaintext or a password, which
// is what `docker login` sends in the password field.
//
// When the credential is a token the username is ignored. The token alone
// identifies the principal, so requiring a matching username would add no
// security — anyone holding the token could supply the right name — while
// producing confusing 401s for the placeholder names clients conventionally
// use (`token`, a bot name, the token's own label).
func (a *Authenticator) AuthenticateCredential(ctx context.Context, username, credential string) (*Principal, error) {
	if _, _, ok := SplitToken(credential); ok {
		return a.AuthenticateToken(ctx, credential)
	}
	return a.AuthenticatePassword(ctx, username, credential)
}

// AuthenticateSession resolves a web session cookie to a principal.
func (a *Authenticator) AuthenticateSession(ctx context.Context, sessionID string) (*Principal, error) {
	s, err := a.DB.GetSession(ctx, sessionID)
	if err != nil {
		return nil, ErrBadCredentials
	}
	u, err := a.DB.GetUser(ctx, s.UserID)
	if err != nil || u.Disabled {
		return nil, ErrBadCredentials
	}
	return principalForUser(u), nil
}

// NewSessionID returns an opaque, unguessable session identifier.
func NewSessionID() (string, error) { return NewSecret(32) }

// ---------------------------------------------------------------- revocation

// revalidateInterval is how stale the answer to "is this account still usable"
// may get on the bearer-token path. It bounds the window in which a disabled
// account or a revoked token keeps working.
const revalidateInterval = 30 * time.Second

type validityKey struct{ userID, tokenID int64 }

// StillValid reports whether a principal recovered from a signed bearer token
// is still backed by a usable account and token.
//
// A bearer token is verified by its signature alone, which is what keeps a pull
// of a hundred layers from becoming a hundred database round trips. The cost is
// that disabling an account or revoking a token has no effect on one until it
// expires. Re-checking on a short cache splits the difference: the hot path
// still answers from memory, and revocation takes effect within
// revalidateInterval rather than a whole token lifetime.
func (a *Authenticator) StillValid(ctx context.Context, userID, tokenID int64) bool {
	if userID == 0 {
		return true // anonymous: there is no account to disable
	}
	key := validityKey{userID, tokenID}
	now := time.Now()

	a.validMu.Lock()
	if checked, ok := a.lastValid[key]; ok && now.Sub(checked) < revalidateInterval {
		a.validMu.Unlock()
		return true
	}
	a.validMu.Unlock()

	u, err := a.DB.GetUser(ctx, userID)
	if err != nil || u.Disabled {
		a.forget(key)
		return false
	}
	if tokenID != 0 {
		t, err := a.DB.GetToken(ctx, tokenID)
		if err != nil || !t.Active() {
			a.forget(key)
			return false
		}
	}

	a.validMu.Lock()
	a.lastValid[key] = now
	a.validMu.Unlock()
	return true
}

func (a *Authenticator) forget(key validityKey) {
	a.validMu.Lock()
	delete(a.lastValid, key)
	a.validMu.Unlock()
}
