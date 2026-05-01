package migrations

import (
	"context"
	"database/sql"
	"errors"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upAddUserAuthType, downAddUserAuthType)
}

func upAddUserAuthType(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
ALTER TABLE user ADD COLUMN auth_type VARCHAR NOT NULL DEFAULT 'local';
`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS idx_user_auth_type ON user(auth_type);
`)
	return err
}

func downAddUserAuthType(ctx context.Context, tx *sql.Tx) error {
	// Refuse to roll back if any LDAP-backed user exists in the DB. The up
	// migration plus the runtime ClearPassword path together leave LDAP
	// users with `password=''`; the original directory passwords cannot be
	// restored. Dropping `auth_type` would silently turn those rows into
	// local accounts whose stored password is empty — and the auth path
	// would happily accept an empty supplied password as a successful
	// login. Force the operator to triage manually instead.
	var ldapCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user WHERE auth_type = 'ldap'`).Scan(&ldapCount); err != nil {
		return err
	}
	if ldapCount > 0 {
		return errors.New("refusing to drop auth_type: LDAP-backed users exist with empty passwords; restore directory passwords or delete those rows before rolling back")
	}
	_, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS idx_user_auth_type;`)
	if err != nil {
		return err
	}
	// SQLite supports DROP COLUMN as of 3.35; this version of Navidrome's
	// minimum SQLite is well above that.
	_, err = tx.ExecContext(ctx, `ALTER TABLE user DROP COLUMN auth_type;`)
	return err
}
