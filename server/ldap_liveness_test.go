package server

import (
	"context"
	"errors"
	"strings"

	"github.com/Masterminds/squirrel"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("LDAP liveness check", func() {
	var (
		ds               *tests.MockDataStore
		users            model.UserRepository
		appPwds          model.AppPasswordRepository
		originalHost     string
		originalSearch   string
		originalDisabled string
	)

	BeforeEach(func() {
		ds = &tests.MockDataStore{}
		users = ds.User(context.Background())
		appPwds = ds.AppPassword(context.Background())
		originalHost = conf.Server.LDAP.Host
		originalSearch = conf.Server.LDAP.SearchFilter
		originalDisabled = conf.Server.LDAP.DisabledFilter
	})

	AfterEach(func() {
		conf.Server.LDAP.Host = originalHost
		conf.Server.LDAP.SearchFilter = originalSearch
		conf.Server.LDAP.DisabledFilter = originalDisabled
	})

	// Helper: seed one LDAP user with one active app password.
	seedLDAPUser := func(id, username string) {
		Expect(users.Put(&model.User{
			ID:       id,
			UserName: username,
			AuthType: model.AuthTypeLDAP,
		})).To(Succeed())
		Expect(users.ClearPassword(id)).To(Succeed())
		Expect(appPwds.Put(&model.AppPassword{
			UserID:      id,
			Name:        "iPhone",
			NewPassword: "secret-" + id,
		})).To(Succeed())
	}

	// Helper: count active app passwords for a given user.
	activeCount := func(userID string) int {
		active, err := appPwds.FindActiveByUser(userID)
		Expect(err).ToNot(HaveOccurred())
		return len(active)
	}

	// Helper: load every LDAP-backed user from the mock store, mirroring
	// the production query in LDAPLivenessCheck.
	loadLDAPUsers := func() model.Users {
		out, err := ds.User(context.Background()).GetAll(model.QueryOptions{
			Filters: squirrel.Eq{"auth_type": model.AuthTypeLDAP},
		})
		Expect(err).ToNot(HaveOccurred())
		return out
	}

	Context("LDAPLivenessCheck top-level", func() {
		It("is a no-op when LDAP.Host is not configured", func() {
			conf.Server.LDAP.Host = ""
			seedLDAPUser("u1", "alice")

			LDAPLivenessCheck(context.Background(), ds)

			Expect(activeCount("u1")).To(Equal(1))
		})

		It("does not dial LDAP when there are no LDAP-backed users", func() {
			// Pointing at an unresolvable host would fail the run if a
			// dial were attempted; instead, the user-load short-circuits
			// before dial and the run completes cleanly.
			conf.Server.LDAP.Host = "ldap://invalid-host-that-does-not-resolve:389"

			Expect(func() {
				LDAPLivenessCheck(context.Background(), ds)
			}).ToNot(Panic())
		})

		It("aborts the run on dial failure without revoking anything", func() {
			conf.Server.LDAP.Host = "ldap://invalid-host-that-does-not-resolve:389"
			seedLDAPUser("u1", "alice")

			LDAPLivenessCheck(context.Background(), ds)

			Expect(activeCount("u1")).To(Equal(1))
		})
	})

	Context("runLDAPLivenessCheck core loop", func() {
		It("revokes app passwords for users the directory reports missing", func() {
			seedLDAPUser("u-missing", "ghost")
			seedLDAPUser("u-active", "alive")

			probe := func(name string) (bool, string, error) {
				if name == "ghost" {
					return false, "missing", nil
				}
				return true, "", nil
			}
			runLDAPLivenessCheck(context.Background(), ds, probe, nil, loadLDAPUsers())

			Expect(activeCount("u-missing")).To(Equal(0))
			Expect(activeCount("u-active")).To(Equal(1))
		})

		It("revokes app passwords for users matched by DisabledFilter", func() {
			seedLDAPUser("u-disabled", "fired")

			probe := func(name string) (bool, string, error) {
				return false, "disabled", nil
			}
			runLDAPLivenessCheck(context.Background(), ds, probe, nil, loadLDAPUsers())

			Expect(activeCount("u-disabled")).To(Equal(0))
		})

		It("does not revoke when the probe returns a transient error", func() {
			seedLDAPUser("u-flaky", "flaky")

			probe := func(name string) (bool, string, error) {
				return false, "", errors.New("transient ldap search failure")
			}
			runLDAPLivenessCheck(context.Background(), ds, probe, nil, loadLDAPUsers())

			Expect(activeCount("u-flaky")).To(Equal(1))
		})

		It("ignores non-LDAP users even if they slip through GetAll", func() {
			Expect(users.Put(&model.User{
				ID:          "u-local",
				UserName:    "localuser",
				NewPassword: "local-secret",
			})).To(Succeed())
			Expect(appPwds.Put(&model.AppPassword{
				UserID:      "u-local",
				Name:        "iPad",
				NewPassword: "local-app",
			})).To(Succeed())

			// Pass every user (LDAP and local) directly, simulating a future
			// caller that forgot to scope by auth_type.
			everyone, err := users.GetAll()
			Expect(err).ToNot(HaveOccurred())

			// Probe says "missing" for everyone — should still spare the local user.
			probe := func(name string) (bool, string, error) {
				return false, "missing", nil
			}
			runLDAPLivenessCheck(context.Background(), ds, probe, nil, everyone)

			Expect(activeCount("u-local")).To(Equal(1))
		})

		It("is a no-op when no LDAP users are passed in", func() {
			probeCalls := 0
			probe := func(name string) (bool, string, error) {
				probeCalls++
				return true, "", nil
			}
			runLDAPLivenessCheck(context.Background(), ds, probe, nil, nil)

			Expect(probeCalls).To(Equal(0))
		})

		It("does not log the revoke line when the user had zero app passwords", func() {
			// Seed a user with no app passwords at all.
			Expect(users.Put(&model.User{
				ID:       "u-no-app-pwds",
				UserName: "lonely",
				AuthType: model.AuthTypeLDAP,
			})).To(Succeed())
			Expect(users.ClearPassword("u-no-app-pwds")).To(Succeed())

			hook, cleanup := tests.LogHook()
			defer cleanup()
			log.SetLevel(log.LevelInfo)

			probe := func(name string) (bool, string, error) {
				return false, "missing", nil
			}

			runLDAPLivenessCheck(context.Background(), ds, probe, nil, loadLDAPUsers())

			Expect(activeCount("u-no-app-pwds")).To(Equal(0))

			// No INFO log line about "revoked app passwords" should fire
			// when n == 0 — that line is misleading and noisy on
			// directories with users that never generated app passwords.
			for _, e := range hook.AllEntries() {
				if e.Level == logrus.InfoLevel {
					Expect(e.Message).ToNot(ContainSubstring("revoked app passwords"))
				}
			}
		})

		It("logs the revoke line when at least one app password was revoked", func() {
			seedLDAPUser("u-bye", "bye")

			hook, cleanup := tests.LogHook()
			defer cleanup()
			log.SetLevel(log.LevelInfo)

			probe := func(name string) (bool, string, error) {
				return false, "missing", nil
			}

			runLDAPLivenessCheck(context.Background(), ds, probe, nil, loadLDAPUsers())

			Expect(activeCount("u-bye")).To(Equal(0))

			matched := false
			for _, e := range hook.AllEntries() {
				if e.Level == logrus.InfoLevel && strings.Contains(e.Message, "revoked app passwords") {
					matched = true
					break
				}
			}
			Expect(matched).To(BeTrue(), "expected INFO log line about revoked app passwords")
		})
	})

	Context("admin recompute", func() {
		alwaysActive := func(name string) (bool, string, error) {
			return true, "", nil
		}

		It("promotes a user added to the admin group", func() {
			seedLDAPUser("u-promote", "promote-me")
			adminProbe := func(name string) (bool, error) { return true, nil }

			runLDAPLivenessCheck(context.Background(), ds, alwaysActive, adminProbe, loadLDAPUsers())

			got, err := users.Get("u-promote")
			Expect(err).ToNot(HaveOccurred())
			Expect(got.IsAdmin).To(BeTrue())
		})

		It("demotes a user removed from the admin group", func() {
			Expect(users.Put(&model.User{
				ID:       "u-demote",
				UserName: "demote-me",
				AuthType: model.AuthTypeLDAP,
				IsAdmin:  true,
			})).To(Succeed())
			adminProbe := func(name string) (bool, error) { return false, nil }

			runLDAPLivenessCheck(context.Background(), ds, alwaysActive, adminProbe, loadLDAPUsers())

			got, err := users.Get("u-demote")
			Expect(err).ToNot(HaveOccurred())
			Expect(got.IsAdmin).To(BeFalse())
		})

		It("preserves IsAdmin when the admin probe returns an error", func() {
			Expect(users.Put(&model.User{
				ID:       "u-flaky-admin",
				UserName: "flakyadmin",
				AuthType: model.AuthTypeLDAP,
				IsAdmin:  true,
			})).To(Succeed())
			adminProbe := func(name string) (bool, error) {
				return false, errors.New("transient ldap admin lookup failure")
			}

			runLDAPLivenessCheck(context.Background(), ds, alwaysActive, adminProbe, loadLDAPUsers())

			got, err := users.Get("u-flaky-admin")
			Expect(err).ToNot(HaveOccurred())
			Expect(got.IsAdmin).To(BeTrue())
		})

		It("demotes inactive users that were admin", func() {
			Expect(users.Put(&model.User{
				ID:       "u-gone-admin",
				UserName: "gone",
				AuthType: model.AuthTypeLDAP,
				IsAdmin:  true,
			})).To(Succeed())
			Expect(appPwds.Put(&model.AppPassword{
				UserID: "u-gone-admin", Name: "iPad", NewPassword: "p",
			})).To(Succeed())
			missing := func(name string) (bool, string, error) { return false, "missing", nil }
			adminProbe := func(name string) (bool, error) { return false, nil }

			runLDAPLivenessCheck(context.Background(), ds, missing, adminProbe, loadLDAPUsers())

			got, err := users.Get("u-gone-admin")
			Expect(err).ToNot(HaveOccurred())
			Expect(got.IsAdmin).To(BeFalse())
			Expect(activeCount("u-gone-admin")).To(Equal(0))
		})
	})

	Context("filter helpers", func() {
		BeforeEach(func() {
			conf.Server.LDAP.SearchFilter = "(uid=%s)"
			conf.Server.LDAP.DisabledFilter = ""
		})

		Describe("presenceFilter", func() {
			It("substitutes a plain username into SearchFilter", func() {
				Expect(presenceFilter("alice")).To(Equal("(uid=alice)"))
			})

			It("escapes filter metacharacters in the username", func() {
				// ldap.EscapeFilter renders ( ) as \28 \29 (and * as \2a, \\ as \5c, NUL as \00).
				Expect(presenceFilter("al(ice)")).To(Equal(`(uid=al\28ice\29)`))
				Expect(presenceFilter("a*b")).To(Equal(`(uid=a\2ab)`))
			})

			It("respects a custom SearchFilter template", func() {
				conf.Server.LDAP.SearchFilter = "(&(objectClass=person)(sAMAccountName=%s))"
				Expect(presenceFilter("bob")).To(Equal("(&(objectClass=person)(sAMAccountName=bob))"))
			})
		})

		Describe("disabledFilter", func() {
			It("returns empty when DisabledFilter is empty", func() {
				conf.Server.LDAP.DisabledFilter = ""
				Expect(disabledFilter("alice")).To(Equal(""))
			})

			It("ANDs DisabledFilter onto the presence filter when set", func() {
				conf.Server.LDAP.DisabledFilter = "(loginShell=/sbin/nologin)"
				Expect(disabledFilter("alice")).To(Equal("(&(uid=alice)(loginShell=/sbin/nologin))"))
			})

			It("escapes the username inside the AND clause", func() {
				conf.Server.LDAP.DisabledFilter = "(loginShell=/sbin/nologin)"
				Expect(disabledFilter("al(ice)")).To(Equal(`(&(uid=al\28ice\29)(loginShell=/sbin/nologin))`))
			})
		})
	})
})
