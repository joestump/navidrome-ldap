package server

import (
	"context"
	"fmt"

	"github.com/Masterminds/squirrel"
	"github.com/go-ldap/ldap"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
)

// livenessProbe answers "is this LDAP user still active in the
// directory?" for a given username. The reason describes which negative
// case applied: "missing" if the directory has no entry for the user,
// "disabled" if the entry exists but matched DisabledFilter. err
// indicates a transient failure — callers must NOT treat this as a
// signal to revoke.
type livenessProbe func(userName string) (active bool, reason string, err error)

// LDAPLivenessCheck reconciles every LDAP-backed user against the
// configured directory and revokes the app passwords of users that no
// longer match — either because they were removed from the directory or
// because they match the configured DisabledFilter. LDAP-backed users
// have an empty stored password (PR #11), so revoking app passwords is
// the last credential they had — once their app passwords are gone they
// cannot authenticate via /rest, and web login fails because they are
// no longer in the directory.
//
// On any directory-wide failure (dial, service-account bind), the run
// is aborted without revoking anything; the next scheduled tick will
// retry. Per-user search errors log a warning and skip just that user.
func LDAPLivenessCheck(ctx context.Context, ds model.DataStore) {
	if conf.Server.LDAP.Host == "" {
		return
	}

	l, err := ldap.DialURL(conf.Server.LDAP.Host)
	if err != nil {
		log.Warn(ctx, "LDAP liveness: dial failed; skipping run", "host", conf.Server.LDAP.Host, err)
		return
	}
	defer l.Close()

	if err := l.Bind(conf.Server.LDAP.BindDN, conf.Server.LDAP.BindPassword); err != nil {
		log.Warn(ctx, "LDAP liveness: service-account bind failed; skipping run", "bindDN", conf.Server.LDAP.BindDN, err)
		return
	}

	runLDAPLivenessCheck(ctx, ds, ldapProbe(l))
}

// runLDAPLivenessCheck is the testable core: given a probe, walk every
// LDAP-backed user and revoke app passwords for ones that don't pass.
func runLDAPLivenessCheck(ctx context.Context, ds model.DataStore, probe livenessProbe) {
	userRepo := ds.User(ctx)
	users, err := userRepo.GetAll(model.QueryOptions{
		Filters: squirrel.Eq{"auth_type": model.AuthTypeLDAP},
	})
	if err != nil {
		log.Error(ctx, "LDAP liveness: failed to load LDAP users", err)
		return
	}
	if len(users) == 0 {
		return
	}

	appRepo := ds.AppPassword(ctx)
	checked := 0
	revoked := 0
	for _, u := range users {
		// Defense-in-depth: the SQL filter above should have done this,
		// but never revoke a local user's app passwords just because a
		// future caller forgot to scope the query.
		if !u.IsLDAP() {
			continue
		}
		active, reason, err := probe(u.UserName)
		if err != nil {
			log.Warn(ctx, "LDAP liveness: probe failed; skipping user", "user", u.UserName, err)
			continue
		}
		checked++
		if active {
			continue
		}

		n, err := appRepo.RevokeAllForUser(u.ID)
		if err != nil {
			log.Error(ctx, "LDAP liveness: failed to revoke app passwords", "user", u.UserName, err)
			continue
		}
		revoked++
		log.Info(ctx, "LDAP liveness: revoked app passwords for user no longer authorized",
			"user", u.UserName, "reason", reason, "appPasswords", n)
	}
	log.Debug(ctx, "LDAP liveness: run complete", "users", len(users), "checked", checked, "revoked", revoked)
}

// ldapProbe builds a livenessProbe that consults the given LDAP
// connection. The connection must already be bound as the service
// account.
func ldapProbe(l *ldap.Conn) livenessProbe {
	return func(userName string) (active bool, reason string, err error) {
		base := conf.Server.LDAP.Base
		userFilter := fmt.Sprintf(conf.Server.LDAP.SearchFilter, ldap.EscapeFilter(userName))

		// Does the user exist in the directory at all?
		sr, err := l.Search(ldap.NewSearchRequest(
			base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			userFilter, []string{"dn"}, nil,
		))
		if err != nil {
			return false, "", err
		}
		if len(sr.Entries) == 0 {
			return false, "missing", nil
		}

		// User exists. If DisabledFilter is set, check whether they match it.
		// Don't penalize the user for a transient search error here:
		// assume active and reconcile on the next tick rather than
		// revoking based on a flaky directory response.
		if df := conf.Server.LDAP.DisabledFilter; df != "" {
			disabledFilter := "(&" + userFilter + df + ")"
			sr2, searchErr := l.Search(ldap.NewSearchRequest(
				base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				disabledFilter, []string{"dn"}, nil,
			))
			if searchErr == nil && len(sr2.Entries) > 0 {
				return false, "disabled", nil
			}
		}

		return true, "", nil
	}
}
