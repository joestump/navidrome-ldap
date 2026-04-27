package subsonic

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http/httptest"

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
})
