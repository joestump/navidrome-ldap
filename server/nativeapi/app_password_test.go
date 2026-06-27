package nativeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/navidrome/navidrome/conf/configtest"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/server"
	"github.com/navidrome/navidrome/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("App Password API", func() {
	var ds model.DataStore
	var router http.Handler
	var adminUser, ownerUser, otherUser model.User

	BeforeEach(func() {
		DeferCleanup(configtest.SetupConfig())
		ds = &tests.MockDataStore{}
		auth.Init(ds)
		nativeRouter := New(ds, nil, nil, nil, tests.NewMockLibraryService(), tests.NewMockUserService(), nil, nil, nil)
		router = server.JWTVerifier(nativeRouter)

		adminUser = model.User{ID: "admin-1", UserName: "admin", Name: "Admin", IsAdmin: true, NewPassword: "p"}
		ownerUser = model.User{ID: "user-1", UserName: "owner", Name: "Owner", IsAdmin: false, NewPassword: "p"}
		otherUser = model.User{ID: "user-2", UserName: "other", Name: "Other", IsAdmin: false, NewPassword: "p"}

		Expect(ds.User(context.TODO()).Put(&adminUser)).To(Succeed())
		Expect(ds.User(context.TODO()).Put(&ownerUser)).To(Succeed())
		Expect(ds.User(context.TODO()).Put(&otherUser)).To(Succeed())
	})

	tokenFor := func(u *model.User) string {
		t, err := auth.CreateToken(u)
		Expect(err).ToNot(HaveOccurred())
		return t
	}

	Describe("POST /api/user/{id}/app-password", func() {
		It("creates an app password for the owner and returns the secret once", func() {
			body := bytes.NewBufferString(`{"name":"iPhone Tempus"}`)
			req := createAuthenticatedRequest("POST", "/user/user-1/app-password", body, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusCreated))
			var resp map[string]any
			Expect(json.Unmarshal(w.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["id"]).ToNot(BeEmpty())
			Expect(resp["userId"]).To(Equal("user-1"))
			Expect(resp["name"]).To(Equal("iPhone Tempus"))
			Expect(resp["secret"]).ToNot(BeEmpty())
		})

		It("lets an admin create on behalf of any user", func() {
			body := bytes.NewBufferString(`{"name":"admin-created"}`)
			req := createAuthenticatedRequest("POST", "/user/user-1/app-password", body, tokenFor(&adminUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusCreated))
		})

		It("forbids a non-admin from creating for another user", func() {
			body := bytes.NewBufferString(`{"name":"sneaky"}`)
			req := createAuthenticatedRequest("POST", "/user/user-2/app-password", body, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusForbidden))
		})

		It("rejects requests without a name", func() {
			body := bytes.NewBufferString(`{}`)
			req := createAuthenticatedRequest("POST", "/user/user-1/app-password", body, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusBadRequest))
		})

		It("returns 401 when unauthenticated", func() {
			body := bytes.NewBufferString(`{"name":"x"}`)
			req := createUnauthenticatedRequest("POST", "/user/user-1/app-password", body)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusUnauthorized))
		})
	})

	Describe("GET /api/user/{id}/app-password", func() {
		It("returns the user's own list", func() {
			Expect(ds.AppPassword(context.TODO()).Put(&model.AppPassword{
				UserID: "user-1", Name: "list-me", NewPassword: "secret",
			})).To(Succeed())

			req := createAuthenticatedRequest("GET", "/user/user-1/app-password", nil, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Body.String()).To(ContainSubstring("list-me"))
			// Plaintext secret must never appear in a list response.
			Expect(w.Body.String()).ToNot(ContainSubstring("secret"))
		})

		It("forbids a non-admin from listing another user's passwords", func() {
			req := createAuthenticatedRequest("GET", "/user/user-2/app-password", nil, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusForbidden))
		})

		It("lets an admin list for any user", func() {
			req := createAuthenticatedRequest("GET", "/user/user-1/app-password", nil, tokenFor(&adminUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
		})
	})

	Describe("DELETE /api/user/{id}/app-password/{appId}", func() {
		It("revokes the password when called by the owner", func() {
			ap := &model.AppPassword{UserID: "user-1", Name: "to-revoke", NewPassword: "x"}
			Expect(ds.AppPassword(context.TODO()).Put(ap)).To(Succeed())

			req := createAuthenticatedRequest("DELETE", "/user/user-1/app-password/"+ap.ID, nil, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))

			active, err := ds.AppPassword(context.TODO()).FindActiveByUser("user-1")
			Expect(err).ToNot(HaveOccurred())
			Expect(active).To(BeEmpty())
		})

		It("rejects a path mismatch where the password belongs to a different user", func() {
			ap := &model.AppPassword{UserID: "user-2", Name: "their-pw", NewPassword: "x"}
			Expect(ds.AppPassword(context.TODO()).Put(ap)).To(Succeed())

			// Admin tries to revoke user-2's password via a /user/user-1/... path.
			// This should 404 because the password isn't owned by user-1.
			req := createAuthenticatedRequest("DELETE", "/user/user-1/app-password/"+ap.ID, nil, tokenFor(&adminUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusNotFound))

			active, err := ds.AppPassword(context.TODO()).FindActiveByUser("user-2")
			Expect(err).ToNot(HaveOccurred())
			Expect(active).To(HaveLen(1))
		})

		It("returns 404 when the app password ID is unknown", func() {
			req := createAuthenticatedRequest("DELETE", "/user/user-1/app-password/does-not-exist", nil, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusNotFound))
		})
	})

	Describe("DELETE /api/user/{id}/app-password (revoke all)", func() {
		It("revokes every active password for the user", func() {
			Expect(ds.AppPassword(context.TODO()).Put(&model.AppPassword{UserID: "user-1", Name: "a", NewPassword: "x"})).To(Succeed())
			Expect(ds.AppPassword(context.TODO()).Put(&model.AppPassword{UserID: "user-1", Name: "b", NewPassword: "y"})).To(Succeed())

			req := createAuthenticatedRequest("DELETE", "/user/user-1/app-password", nil, tokenFor(&ownerUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(w.Body.String()).To(ContainSubstring(`"revoked":2`))

			active, err := ds.AppPassword(context.TODO()).FindActiveByUser("user-1")
			Expect(err).ToNot(HaveOccurred())
			Expect(active).To(BeEmpty())
		})
	})

	Describe("response shape", func() {
		It("never leaks the encrypted password blob via list", func() {
			ap := &model.AppPassword{UserID: "user-1", Name: "blobby", NewPassword: "the-secret-value"}
			Expect(ds.AppPassword(context.TODO()).Put(ap)).To(Succeed())

			req := createAuthenticatedRequest("GET", "/user/user-1/app-password", nil, tokenFor(&adminUser))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			Expect(strings.Contains(w.Body.String(), "the-secret-value")).To(BeFalse())
		})
	})
})
