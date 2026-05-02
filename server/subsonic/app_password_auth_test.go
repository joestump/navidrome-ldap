package subsonic

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http/httptest"

	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("App Password Subsonic Auth", func() {
	var ds *tests.MockDataStore
	var w *httptest.ResponseRecorder
	var nextHandler *mockHandler
	const username = "alice"
	const userID = "uid-alice"
	const mainPassword = "alice-main"
	const appSecret = "tempus-on-iphone-secret"

	BeforeEach(func() {
		nextHandler = &mockHandler{}
		w = httptest.NewRecorder()
		ds = &tests.MockDataStore{}

		Expect(ds.User(context.TODO()).Put(&model.User{
			ID:          userID,
			UserName:    username,
			NewPassword: mainPassword,
		})).To(Succeed())
		Expect(ds.AppPassword(context.TODO()).Put(&model.AppPassword{
			UserID:      userID,
			Name:        "iPhone",
			NewPassword: appSecret,
		})).To(Succeed())
	})

	When("the client sends a legacy password (`p=`)", func() {
		It("accepts the main password", func() {
			r := newGetRequest("u="+username, "p="+mainPassword)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeTrue())
			user, _ := request.UserFrom(nextHandler.req.Context())
			Expect(user.UserName).To(Equal(username))
		})

		It("accepts an active app password as a fallback", func() {
			r := newGetRequest("u="+username, "p="+appSecret)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeTrue())
			user, _ := request.UserFrom(nextHandler.req.Context())
			Expect(user.UserName).To(Equal(username))
		})

		It("rejects an unknown secret", func() {
			r := newGetRequest("u="+username, "p=not-the-right-secret")
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})

		It("rejects a revoked app password", func() {
			active, err := ds.AppPassword(context.TODO()).FindActiveByUser(userID)
			Expect(err).ToNot(HaveOccurred())
			Expect(active).To(HaveLen(1))
			Expect(ds.AppPassword(context.TODO()).Revoke(active[0].ID)).To(Succeed())

			r := newGetRequest("u="+username, "p="+appSecret)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})
	})

	When("the client sends salt+token (`t=`/`s=`)", func() {
		const salt = "saltysalt"

		It("accepts the main password's token", func() {
			token := fmt.Sprintf("%x", md5.Sum([]byte(mainPassword+salt)))
			r := newGetRequest("u="+username, "t="+token, "s="+salt)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeTrue())
		})

		It("accepts an app password's token as a fallback", func() {
			token := fmt.Sprintf("%x", md5.Sum([]byte(appSecret+salt)))
			r := newGetRequest("u="+username, "t="+token, "s="+salt)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeTrue())
			user, _ := request.UserFrom(nextHandler.req.Context())
			Expect(user.UserName).To(Equal(username))
		})

		It("rejects when neither the main password nor any app password matches", func() {
			token := fmt.Sprintf("%x", md5.Sum([]byte("nope"+salt)))
			r := newGetRequest("u="+username, "t="+token, "s="+salt)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})

		It("rejects revoked app password tokens", func() {
			active, err := ds.AppPassword(context.TODO()).FindActiveByUser(userID)
			Expect(err).ToNot(HaveOccurred())
			Expect(ds.AppPassword(context.TODO()).Revoke(active[0].ID)).To(Succeed())

			token := fmt.Sprintf("%x", md5.Sum([]byte(appSecret+salt)))
			r := newGetRequest("u="+username, "t="+token, "s="+salt)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
		})
	})

	When("the user has no app passwords", func() {
		It("does not interfere with main-password auth", func() {
			Expect(ds.User(context.TODO()).Put(&model.User{
				ID:          "uid-bob",
				UserName:    "bob",
				NewPassword: "bobpw",
			})).To(Succeed())

			r := newGetRequest("u=bob", "p=bobpw")
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeTrue())
		})

		It("rejects an invalid main password without trying app passwords", func() {
			Expect(ds.User(context.TODO()).Put(&model.User{
				ID:          "uid-bob",
				UserName:    "bob",
				NewPassword: "bobpw",
			})).To(Succeed())

			r := newGetRequest("u=bob", "p=wrong")
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
		})
	})

	It("bumps last_used_at on a successful app-password auth", func() {
		token := fmt.Sprintf("%x", md5.Sum([]byte(appSecret+"saltysalt")))
		r := newGetRequest("u="+username, "t="+token, "s=saltysalt")
		authenticate(ds)(nextHandler).ServeHTTP(w, r)

		Expect(nextHandler.called).To(BeTrue())
		all, err := ds.AppPassword(context.TODO()).List(userID)
		Expect(err).ToNot(HaveOccurred())
		Expect(all).To(HaveLen(1))
		Expect(all[0].LastUsedAt).ToNot(BeNil())
	})

	// Regression: app-password auth must short-circuit BEFORE
	// `server.ValidateLogin` is called. ValidateLogin attempts a real LDAP
	// bind and, on success, bumps LastLoginAt. If app-password auth runs
	// before ValidateLogin (the intended order), neither LDAP nor
	// LastLoginAt is touched.
	It("does not bump LastLoginAt when authenticating via app password (LDAP-skip)", func() {
		r := newGetRequest("u="+username, "p="+appSecret)
		authenticate(ds)(nextHandler).ServeHTTP(w, r)

		Expect(nextHandler.called).To(BeTrue())
		usr, err := ds.User(context.TODO()).FindByUsername(username)
		Expect(err).ToNot(HaveOccurred())
		Expect(usr.LastLoginAt).To(BeNil(),
			"LastLoginAt should not be set — that would mean ValidateLogin "+
				"ran, which means LDAP would have been queried")
	})

	// Regression for the single-decode invariant. The parent flow decodes
	// `p=enc:<hex>` once into plaintext; matchAppPassword must not decode
	// again. A password whose plaintext literally starts with `enc:`
	// followed by hex would otherwise be mishandled by a double-decode.
	It("matches an app password whose plaintext starts with `enc:`", func() {
		// Plaintext that looks like an `enc:`-encoded value but isn't.
		const trickyPlaintext = "enc:6162"
		Expect(ds.AppPassword(context.TODO()).Put(&model.AppPassword{
			UserID:      userID,
			Name:        "tricky",
			NewPassword: trickyPlaintext,
		})).To(Succeed())

		// hex-encode the literal string "enc:6162" so the parent flow
		// decodes it once into the plaintext. A buggy double-decode would
		// take the decoded "enc:6162" and decode again to "ab".
		hexEncoded := fmt.Sprintf("%x", []byte(trickyPlaintext))
		r := newGetRequest("u="+username, "p=enc:"+hexEncoded)
		authenticate(ds)(nextHandler).ServeHTTP(w, r)

		Expect(nextHandler.called).To(BeTrue())
	})

	// LDAP-backed users may not authenticate Subsonic clients with their
	// directory password — only with an app password. (Issue #7.)
	When("the user is LDAP-backed", func() {
		const ldapUser = "ldapper"
		const ldapUserID = "uid-ldapper"
		const ldapDirPlaintext = "directory-plaintext"
		const ldapAppPlaintext = "ldap-tempus-app-plaintext"

		BeforeEach(func() {
			Expect(ds.User(context.TODO()).Put(&model.User{
				ID:       ldapUserID,
				UserName: ldapUser,
				AuthType: model.AuthTypeLDAP,
				// LDAP users have no persisted password, but set one
				// here to prove that even if it leaks back into the DB,
				// it cannot be used for /rest auth.
				NewPassword: ldapDirPlaintext,
			})).To(Succeed())
			Expect(ds.AppPassword(context.TODO()).Put(&model.AppPassword{
				UserID:      ldapUserID,
				Name:        "iPhone",
				NewPassword: ldapAppPlaintext,
			})).To(Succeed())
		})

		It("accepts the app password", func() {
			r := newGetRequest("u="+ldapUser, "p="+ldapAppPlaintext)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeTrue())
		})

		It("rejects the LDAP directory password via legacy `p=` auth", func() {
			r := newGetRequest("u="+ldapUser, "p="+ldapDirPlaintext)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})

		It("rejects the LDAP directory password via salt+token", func() {
			token := fmt.Sprintf("%x", md5.Sum([]byte(ldapDirPlaintext+"saltysalt")))
			r := newGetRequest("u="+ldapUser, "t="+token, "s=saltysalt")
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})

		// Regression for the bug PR #20 fixes: LDAP users have an empty
		// stored password, so salt+token over the empty password is
		// rejected by the LDAP-app-password gate. The web UI uses JWT
		// (?jwt=) instead — verify it works end-to-end through the
		// authenticate middleware for an LDAP user with no app password
		// in play.
		It("accepts a JWT minted for the LDAP user", func() {
			auth.Init(ds)
			ldapUsr, err := ds.User(context.TODO()).FindByUsername(ldapUser)
			Expect(err).ToNot(HaveOccurred())
			jwt, err := auth.CreateToken(ldapUsr)
			Expect(err).ToNot(HaveOccurred())

			r := newGetRequest("u="+ldapUser, "jwt="+jwt)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeTrue())
			user, _ := request.UserFrom(nextHandler.req.Context())
			Expect(user.UserName).To(Equal(ldapUser))
		})
	})

	// Defense-in-depth against empty-password authentication. A user whose
	// stored `password` column is empty (LDAP user post-ClearPassword, a
	// row mid-migration, etc.) must never authenticate via /rest with an
	// empty submitted credential.
	When("the user's stored password is empty", func() {
		const emptyUser = "scrubbed"
		const emptyUserID = "uid-scrubbed"

		BeforeEach(func() {
			Expect(ds.User(context.TODO()).Put(&model.User{
				ID:       emptyUserID,
				UserName: emptyUser,
			})).To(Succeed())
			Expect(ds.User(context.TODO()).ClearPassword(emptyUserID)).To(Succeed())
		})

		It("rejects empty `p=`", func() {
			r := newGetRequest("u="+emptyUser, "p=")
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})

		It("rejects an `enc:` value that decodes to empty", func() {
			r := newGetRequest("u="+emptyUser, "p=enc:")
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})

		It("rejects salt+token computed from an empty password", func() {
			const salt = "saltysalt"
			token := fmt.Sprintf("%x", md5.Sum([]byte(""+salt)))
			r := newGetRequest("u="+emptyUser, "t="+token, "s="+salt)
			authenticate(ds)(nextHandler).ServeHTTP(w, r)

			Expect(nextHandler.called).To(BeFalse())
			Expect(w.Body.String()).To(ContainSubstring(`code="40"`))
		})
	})
})
