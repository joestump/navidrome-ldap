package migrations

import (
	"context"
	"database/sql"

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
	_, err := tx.ExecContext(ctx, `DROP INDEX IF EXISTS idx_user_auth_type;`)
	if err != nil {
		return err
	}
	// SQLite supports DROP COLUMN as of 3.35; this version of Navidrome's
	// minimum SQLite is well above that.
	_, err = tx.ExecContext(ctx, `ALTER TABLE user DROP COLUMN auth_type;`)
	return err
}
