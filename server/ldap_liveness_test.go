package server

import (
	"context"
	"errors"

	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("LDAP liveness check", func() {
	var (
		ds       *tests.MockDataStore
		users    model.UserRepository
		appPwds  model.AppPasswordRepository
		original string
	)

	BeforeEach(func() {
		ds = &tests.MockDataStore{}
		users = ds.User(context.Background())
		appPwds = ds.AppPassword(context.Background())
		original = conf.Server.LDAP.Host
	})

	AfterEach(func() {
		conf.Server.LDAP.Host = original
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

	Context("LDAPLivenessCheck top-level", func() {
		It("is a no-op when LDAP.Host is not configured", func() {
			conf.Server.LDAP.Host = ""
			seedLDAPUser("u1", "alice")

			LDAPLivenessCheck(context.Background(), ds)

			Expect(activeCount("u1")).To(Equal(1))
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
			runLDAPLivenessCheck(context.Background(), ds, probe)

			Expect(activeCount("u-missing")).To(Equal(0))
			Expect(activeCount("u-active")).To(Equal(1))
		})

		It("revokes app passwords for users matched by DisabledFilter", func() {
			seedLDAPUser("u-disabled", "fired")

			probe := func(name string) (bool, string, error) {
				return false, "disabled", nil
			}
			runLDAPLivenessCheck(context.Background(), ds, probe)

			Expect(activeCount("u-disabled")).To(Equal(0))
		})

		It("does not revoke when the probe returns a transient error", func() {
			seedLDAPUser("u-flaky", "flaky")

			probe := func(name string) (bool, string, error) {
				return false, "", errors.New("transient ldap search failure")
			}
			runLDAPLivenessCheck(context.Background(), ds, probe)

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

			// Probe says "missing" for everyone — should still spare the local user.
			probe := func(name string) (bool, string, error) {
				return false, "missing", nil
			}
			runLDAPLivenessCheck(context.Background(), ds, probe)

			Expect(activeCount("u-local")).To(Equal(1))
		})

		It("is a no-op when no LDAP users are present", func() {
			probeCalls := 0
			probe := func(name string) (bool, string, error) {
				probeCalls++
				return true, "", nil
			}
			runLDAPLivenessCheck(context.Background(), ds, probe)

			Expect(probeCalls).To(Equal(0))
		})
	})
})
