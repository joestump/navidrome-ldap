package persistence

import (
	"context"
	"errors"
	"fmt"
	"time"

	. "github.com/Masterminds/squirrel"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"github.com/navidrome/navidrome/utils"
	"github.com/pocketbase/dbx"
)

type appPasswordRepository struct {
	sqlRepository
}

func NewAppPasswordRepository(ctx context.Context, db dbx.Builder) model.AppPasswordRepository {
	r := &appPasswordRepository{}
	r.ctx = ctx
	r.db = db
	r.tableName = "user_app_password"
	// Ensure the shared encryption key has been initialized. The user
	// repository normally does this on first use; in code paths that touch
	// app passwords before any user repository is constructed we need it
	// here too.
	once.Do(func() {
		ur := &userRepository{}
		ur.ctx = ctx
		ur.db = db
		ur.tableName = "user"
		_ = ur.initPasswordEncryptionKey()
	})
	return r
}

func (r *appPasswordRepository) Put(ap *model.AppPassword) error {
	if ap.UserID == "" {
		return errors.New("user_id is required")
	}
	if ap.Name == "" {
		return errors.New("name is required")
	}
	if ap.NewPassword == "" {
		return errors.New("password is required")
	}
	if ap.ID == "" {
		ap.ID = id.NewRandom()
	}
	if ap.CreatedAt.IsZero() {
		ap.CreatedAt = time.Now()
	}

	encrypted, err := utils.Encrypt(r.ctx, encKey, ap.NewPassword)
	if err != nil {
		return fmt.Errorf("encrypting app password: %w", err)
	}
	plain := ap.NewPassword
	ap.NewPassword = encrypted
	defer func() {
		// Restore the in-memory plaintext for the caller (one-time display)
		// and clear NewPassword so it can't accidentally be reused.
		ap.Password = plain
		ap.NewPassword = ""
	}()

	values, err := toSQLArgs(*ap)
	if err != nil {
		return fmt.Errorf("converting app password to SQL args: %w", err)
	}
	insert := Insert(r.tableName).SetMap(values)
	if _, err := r.executeSQL(insert); err != nil {
		return err
	}
	return nil
}

func (r *appPasswordRepository) Get(idVal string) (*model.AppPassword, error) {
	sel := r.newSelect().Columns("*").Where(Eq{"id": idVal})
	var res model.AppPassword
	if err := r.queryOne(sel, &res); err != nil {
		return nil, err
	}
	// Get is intended for callers who need metadata only (ownership checks,
	// UI display). The encrypted blob never leaves the package — auth uses
	// FindActiveByUser, which decrypts.
	res.Password = ""
	return &res, nil
}

func (r *appPasswordRepository) List(userID string) (model.AppPasswords, error) {
	sel := r.newSelect().Columns("*").Where(Eq{"user_id": userID}).OrderBy("created_at DESC")
	var res model.AppPasswords
	if err := r.queryAll(sel, &res); err != nil {
		return nil, err
	}
	// Never expose the encrypted blob via List — it's only used internally.
	for i := range res {
		res[i].Password = ""
	}
	return res, nil
}

func (r *appPasswordRepository) FindActiveByUser(userID string) (model.AppPasswords, error) {
	sel := r.newSelect().Columns("*").
		Where(Eq{"user_id": userID}).
		Where(Eq{"revoked_at": nil})
	var res model.AppPasswords
	if err := r.queryAll(sel, &res); err != nil {
		return nil, err
	}
	for i := range res {
		plain, err := utils.Decrypt(r.ctx, encKey, res[i].Password)
		if err != nil {
			log.Error(r.ctx, "Error decrypting app password", "id", res[i].ID, "userID", userID, err)
			continue
		}
		res[i].Password = plain
	}
	return res, nil
}

func (r *appPasswordRepository) Revoke(idVal string) error {
	upd := Update(r.tableName).
		Where(Eq{"id": idVal}).
		Where(Eq{"revoked_at": nil}).
		Set("revoked_at", time.Now())
	count, err := r.executeSQL(upd)
	if err != nil {
		return err
	}
	if count == 0 {
		return model.ErrNotFound
	}
	return nil
}

func (r *appPasswordRepository) RevokeAllForUser(userID string) (int64, error) {
	upd := Update(r.tableName).
		Where(Eq{"user_id": userID}).
		Where(Eq{"revoked_at": nil}).
		Set("revoked_at", time.Now())
	return r.executeSQL(upd)
}

func (r *appPasswordRepository) Touch(idVal string) error {
	// Filter on revoked_at to avoid bumping last_used_at on a revoked row
	// under a TOCTOU race (a request mid-auth completing after another
	// request revokes the same app password). Misleading audit data
	// otherwise.
	upd := Update(r.tableName).
		Where(Eq{"id": idVal}).
		Where(Eq{"revoked_at": nil}).
		Set("last_used_at", time.Now())
	_, err := r.executeSQL(upd)
	return err
}

var _ model.AppPasswordRepository = (*appPasswordRepository)(nil)
