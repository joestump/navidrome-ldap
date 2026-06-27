package model

import "time"

// AppPassword is a per-device credential a user can generate for use with
// Subsonic API clients. It is independent of the user's main password (LDAP or
// local) and can be revoked individually without affecting any other client or
// the user's primary credentials.
//
// Password is the in-memory plaintext, populated only when the secret is
// generated (Put) or fetched for authentication (FindActiveByUser). It is
// never serialized to JSON. NewPassword carries the plaintext from caller to
// repository on Put and is encrypted at rest, mirroring the User model.
type AppPassword struct {
	ID          string     `structs:"id" json:"id"`
	UserID      string     `structs:"user_id" json:"userId"`
	Name        string     `structs:"name" json:"name"`
	Password    string     `structs:"-" json:"-"`
	NewPassword string     `structs:"password,omitempty" json:"-"`
	CreatedAt   time.Time  `structs:"created_at" json:"createdAt"`
	LastUsedAt  *time.Time `structs:"last_used_at" json:"lastUsedAt,omitempty"`
	RevokedAt   *time.Time `structs:"revoked_at" json:"revokedAt,omitempty"`
}

// IsActive reports whether the app password has not been revoked.
func (a AppPassword) IsActive() bool {
	return a.RevokedAt == nil
}

type AppPasswords []AppPassword

// AppPasswordRepository persists per-device app passwords.
//
// Put creates the record (assigning ID/CreatedAt) and encrypts NewPassword in
// place. List returns metadata only (no plaintext). FindActiveByUser returns
// active records with Password decrypted, suitable for the Subsonic auth
// fallback. Touch updates LastUsedAt to support last-used UI display. Revoke
// performs a soft revocation (sets RevokedAt); the row remains so audit trails
// and last-used timestamps survive.
type AppPasswordRepository interface {
	Put(ap *AppPassword) error
	Get(id string) (*AppPassword, error)
	List(userID string) (AppPasswords, error)
	FindActiveByUser(userID string) (AppPasswords, error)
	Revoke(id string) error
	RevokeAllForUser(userID string) (int64, error)
	Touch(id string) error
}
