package server

import (
	"fmt"

	"github.com/go-ldap/ldap"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
)

// adminCheckEnabled reports whether the operator has configured an
// LDAP-driven admin policy. When this returns false, the login flow
// and the liveness sweep leave IsAdmin alone — the value persisted in
// the user table is authoritative.
func adminCheckEnabled() bool {
	return conf.Server.LDAP.AdminGroup != "" || conf.Server.LDAP.AdminFilter != ""
}

// buildAdminFilter constructs the LDAP filter used to determine
// whether the named user is an admin. Returns "" if no admin policy is
// configured (caller must check adminCheckEnabled first). Extracted as
// a pure function so the filter shape can be unit-tested without an
// LDAP connection.
func buildAdminFilter(userName string) string {
	escaped := ldap.EscapeFilter(userName)
	if g := conf.Server.LDAP.AdminGroup; g != "" {
		userFilter := fmt.Sprintf(conf.Server.LDAP.SearchFilter, escaped)
		return "(&(memberOf=" + ldap.EscapeFilter(g) + ")" + userFilter + ")"
	}
	if af := conf.Server.LDAP.AdminFilter; af != "" {
		return fmt.Sprintf(af, escaped)
	}
	return ""
}

// ldapAdminCheck searches the directory to determine whether the named
// user should be granted Navidrome admin. The bound LDAP connection l
// must already be authenticated as the service account — group-membership
// reads typically require it. Caller MUST first check adminCheckEnabled()
// and skip this call when no admin policy is set.
//
// On a transient lookup error, callers MUST preserve the existing
// IsAdmin value rather than demote — this avoids a directory hiccup
// silently locking the operator out of admin functions.
func ldapAdminCheck(l *ldap.Conn, userName string) (isAdmin bool, err error) {
	filter := buildAdminFilter(userName)
	if filter == "" {
		// Caller should have checked adminCheckEnabled. Treat as no-op.
		return false, nil
	}
	sr, err := l.Search(ldap.NewSearchRequest(
		conf.Server.LDAP.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"dn"}, nil,
	))
	if err != nil {
		return false, err
	}
	return len(sr.Entries) > 0, nil
}

// applyLDAPAdminResult applies the outcome of an admin-membership lookup
// to the user's IsAdmin flag. A nil result means the lookup was skipped
// (admin policy not configured) or failed transiently — in both cases
// the existing IsAdmin is preserved so a directory hiccup can't lock the
// operator out. A non-nil pointer is the authoritative result and
// overwrites IsAdmin in either direction (promote or demote).
func applyLDAPAdminResult(u *model.User, adminCheckResult *bool) {
	if adminCheckResult != nil {
		u.IsAdmin = *adminCheckResult
	}
}
