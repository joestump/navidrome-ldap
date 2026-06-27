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

// adminProbeFn answers "should this LDAP user be a Navidrome admin?"
// based on AdminGroup/AdminFilter configuration. nil indicates that no
// admin policy is configured and the sweep should leave IsAdmin alone.
// A non-nil error indicates a transient lookup failure — callers MUST
// preserve the existing IsAdmin rather than demote.
type adminProbeFn func(userName string) (isAdmin bool, err error)

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

	// Load LDAP-backed users before dialing so we don't burn a TCP+TLS
	// handshake + bind on every tick when there's nothing to reconcile
	// (just-after-rollout, mostly-local installs that enabled the feature
	// speculatively, etc.).
	users, err := ds.User(ctx).GetAll(model.QueryOptions{
		Filters: squirrel.Eq{"auth_type": model.AuthTypeLDAP},
	})
	if err != nil {
		log.Error(ctx, "LDAP liveness: failed to load LDAP users", err)
		return
	}
	if len(users) == 0 {
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

	var adminProbe adminProbeFn
	if adminCheckEnabled() {
		adminProbe = func(userName string) (bool, error) {
			return ldapAdminCheck(l, userName)
		}
	}
	runLDAPLivenessCheck(ctx, ds, ldapProbe(l), adminProbe, users)
}

// runLDAPLivenessCheck is the testable core: given a probe and a
// pre-loaded set of LDAP users, walk every user and revoke app
// passwords for ones that don't pass. When adminProbe is non-nil,
// IsAdmin is also recomputed against the directory and persisted on
// change. A transient adminProbe error preserves the existing IsAdmin
// rather than demoting.
func runLDAPLivenessCheck(ctx context.Context, ds model.DataStore, probe livenessProbe, adminProbe adminProbeFn, users model.Users) {
	if len(users) == 0 {
		return
	}

	appRepo := ds.AppPassword(ctx)
	checked := 0
	revoked := 0
	adminChanged := 0
	for _, u := range users {
		// Defense-in-depth: the SQL filter at the call site should have
		// done this, but never revoke a local user's app passwords just
		// because a future caller forgot to scope the query.
		if !u.IsLDAP() {
			continue
		}
		active, reason, err := probe(u.UserName)
		if err != nil {
			log.Warn(ctx, "LDAP liveness: probe failed; skipping user", "user", u.UserName, err)
			continue
		}
		checked++

		if !active {
			n, revokeErr := appRepo.RevokeAllForUser(u.ID)
			if revokeErr != nil {
				log.Error(ctx, "LDAP liveness: failed to revoke app passwords", "user", u.UserName, revokeErr)
			} else {
				revoked++
				if n > 0 {
					// Only log the "revoked" line when there was actually
					// something to revoke. Otherwise an offboarding wave on
					// a directory with few app-password users floods INFO
					// with "appPasswords=0" lines on every tick.
					log.Info(ctx, "LDAP liveness: revoked app passwords for user no longer authorized",
						"user", u.UserName, "reason", reason, "appPasswords", n)
				}
			}
		}

		// Recompute admin membership when configured. We do this for
		// inactive users too: if a removed-from-directory admin later
		// returns without re-validation, their stale IsAdmin should
		// already be cleared.
		if adminProbe != nil {
			newIsAdmin, adminErr := adminProbe(u.UserName)
			if adminErr != nil {
				log.Warn(ctx, "LDAP liveness: admin probe failed; preserving IsAdmin", "user", u.UserName, adminErr)
			} else if u.IsAdmin != newIsAdmin {
				u.IsAdmin = newIsAdmin
				if err := ds.User(ctx).Put(&u); err != nil {
					log.Error(ctx, "LDAP liveness: failed to persist IsAdmin change", "user", u.UserName, err)
				} else {
					adminChanged++
					log.Info(ctx, "LDAP liveness: updated IsAdmin from directory",
						"user", u.UserName, "isAdmin", newIsAdmin)
				}
			}
		}
	}
	log.Debug(ctx, "LDAP liveness: run complete",
		"users", len(users), "checked", checked, "revoked", revoked, "adminChanged", adminChanged)
}

// presenceFilter builds the "does this user exist?" LDAP filter by
// substituting the escaped username into the configured SearchFilter
// template (e.g. "(uid=%s)"). The username is run through
// ldap.EscapeFilter to neutralize filter metacharacters before
// substitution.
func presenceFilter(userName string) string {
	return fmt.Sprintf(conf.Server.LDAP.SearchFilter, ldap.EscapeFilter(userName))
}

// disabledFilter builds the "is this user disabled?" LDAP filter by
// AND-ing the configured DisabledFilter clause onto the presence
// filter for the given username. Returns "" when DisabledFilter is
// empty — the caller should skip the disabled-check search in that
// case.
func disabledFilter(userName string) string {
	df := conf.Server.LDAP.DisabledFilter
	if df == "" {
		return ""
	}
	return "(&" + presenceFilter(userName) + df + ")"
}

// ldapProbe builds a livenessProbe that consults the given LDAP
// connection. The connection must already be bound as the service
// account.
func ldapProbe(l *ldap.Conn) livenessProbe {
	return func(userName string) (active bool, reason string, err error) {
		base := conf.Server.LDAP.Base
		userFilter := presenceFilter(userName)

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
		if df := disabledFilter(userName); df != "" {
			sr2, searchErr := l.Search(ldap.NewSearchRequest(
				base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
				df, []string{"dn"}, nil,
			))
			if searchErr == nil && len(sr2.Entries) > 0 {
				return false, "disabled", nil
			}
		}

		return true, "", nil
	}
}
