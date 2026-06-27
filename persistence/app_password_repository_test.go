package persistence

import (
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AppPasswordRepository", func() {
	var repo model.AppPasswordRepository
	var userRepo model.UserRepository
	var owner model.User

	BeforeEach(func() {
		ctx := log.NewContext(GinkgoT().Context())
		userRepo = NewUserRepository(ctx, GetDBXBuilder())
		owner = model.User{
			ID:          "ap-test-owner",
			UserName:    "ap-test-owner",
			Name:        "AP Test Owner",
			NewPassword: "irrelevant",
		}
		Expect(userRepo.Put(&owner)).To(Succeed())
		repo = NewAppPasswordRepository(ctx, GetDBXBuilder())
		// Wipe any leftover rows from previous specs since the persistence
		// suite shares one in-memory SQLite database across all tests.
		_, err := GetDBXBuilder().NewQuery("DELETE FROM user_app_password").Execute()
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Put", func() {
		It("creates a record, encrypts the secret, and exposes the plaintext on the input", func() {
			ap := &model.AppPassword{
				UserID:      owner.ID,
				Name:        "iPhone Tempus",
				NewPassword: "super-secret",
			}
			Expect(repo.Put(ap)).To(Succeed())
			Expect(ap.ID).ToNot(BeEmpty())
			Expect(ap.CreatedAt).ToNot(BeZero())
			Expect(ap.Password).To(Equal("super-secret"))
			Expect(ap.NewPassword).To(BeEmpty())

			// Confirm the DB stored an encrypted blob, not the plaintext.
			row, err := repo.Get(ap.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(row.Password).To(BeEmpty()) // Get scrubs the encrypted form
			Expect(row.Name).To(Equal("iPhone Tempus"))
		})

		It("rejects records missing required fields", func() {
			Expect(repo.Put(&model.AppPassword{Name: "n", NewPassword: "p"})).ToNot(Succeed())
			Expect(repo.Put(&model.AppPassword{UserID: owner.ID, NewPassword: "p"})).ToNot(Succeed())
			Expect(repo.Put(&model.AppPassword{UserID: owner.ID, Name: "n"})).ToNot(Succeed())
		})

		It("rejects duplicate names for the same user", func() {
			a := &model.AppPassword{UserID: owner.ID, Name: "dup", NewPassword: "x"}
			b := &model.AppPassword{UserID: owner.ID, Name: "dup", NewPassword: "y"}
			Expect(repo.Put(a)).To(Succeed())
			Expect(repo.Put(b)).ToNot(Succeed())
		})
	})

	Describe("FindActiveByUser", func() {
		It("returns active passwords with decrypted plaintext and excludes revoked ones", func() {
			active := &model.AppPassword{UserID: owner.ID, Name: "active", NewPassword: "alpha"}
			toRevoke := &model.AppPassword{UserID: owner.ID, Name: "old", NewPassword: "beta"}
			Expect(repo.Put(active)).To(Succeed())
			Expect(repo.Put(toRevoke)).To(Succeed())
			Expect(repo.Revoke(toRevoke.ID)).To(Succeed())

			results, err := repo.FindActiveByUser(owner.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(results).To(HaveLen(1))
			Expect(results[0].ID).To(Equal(active.ID))
			Expect(results[0].Password).To(Equal("alpha"))
		})

		It("returns empty for a user with no app passwords", func() {
			results, err := repo.FindActiveByUser("no-such-user")
			Expect(err).ToNot(HaveOccurred())
			Expect(results).To(BeEmpty())
		})
	})

	Describe("List", func() {
		It("returns metadata for all of the user's records (including revoked) but never the encrypted blob", func() {
			a := &model.AppPassword{UserID: owner.ID, Name: "list-a", NewPassword: "a"}
			b := &model.AppPassword{UserID: owner.ID, Name: "list-b", NewPassword: "b"}
			Expect(repo.Put(a)).To(Succeed())
			Expect(repo.Put(b)).To(Succeed())
			Expect(repo.Revoke(b.ID)).To(Succeed())

			results, err := repo.List(owner.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(results).To(HaveLen(2))
			for _, r := range results {
				Expect(r.Password).To(BeEmpty())
			}
		})
	})

	Describe("Revoke", func() {
		It("marks an active password revoked", func() {
			ap := &model.AppPassword{UserID: owner.ID, Name: "revoke-me", NewPassword: "x"}
			Expect(repo.Put(ap)).To(Succeed())

			Expect(repo.Revoke(ap.ID)).To(Succeed())

			results, err := repo.FindActiveByUser(owner.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(results).To(BeEmpty())
		})

		It("returns ErrNotFound for an unknown ID", func() {
			Expect(repo.Revoke("does-not-exist")).To(MatchError(model.ErrNotFound))
		})

		It("returns ErrNotFound when revoking an already-revoked password", func() {
			ap := &model.AppPassword{UserID: owner.ID, Name: "double-revoke", NewPassword: "x"}
			Expect(repo.Put(ap)).To(Succeed())
			Expect(repo.Revoke(ap.ID)).To(Succeed())
			Expect(repo.Revoke(ap.ID)).To(MatchError(model.ErrNotFound))
		})
	})

	Describe("RevokeAllForUser", func() {
		It("revokes every active password for the user and reports the count", func() {
			Expect(repo.Put(&model.AppPassword{UserID: owner.ID, Name: "all-1", NewPassword: "x"})).To(Succeed())
			Expect(repo.Put(&model.AppPassword{UserID: owner.ID, Name: "all-2", NewPassword: "y"})).To(Succeed())
			ap3 := &model.AppPassword{UserID: owner.ID, Name: "all-3", NewPassword: "z"}
			Expect(repo.Put(ap3)).To(Succeed())
			Expect(repo.Revoke(ap3.ID)).To(Succeed())

			n, err := repo.RevokeAllForUser(owner.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(n).To(Equal(int64(2)))

			results, err := repo.FindActiveByUser(owner.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(results).To(BeEmpty())
		})

		It("does not affect another user's passwords", func() {
			otherOwner := model.User{ID: "ap-test-other", UserName: "ap-test-other", Name: "Other", NewPassword: "x"}
			Expect(userRepo.Put(&otherOwner)).To(Succeed())
			Expect(repo.Put(&model.AppPassword{UserID: owner.ID, Name: "mine", NewPassword: "x"})).To(Succeed())
			Expect(repo.Put(&model.AppPassword{UserID: otherOwner.ID, Name: "theirs", NewPassword: "y"})).To(Succeed())

			_, err := repo.RevokeAllForUser(owner.ID)
			Expect(err).ToNot(HaveOccurred())

			theirs, err := repo.FindActiveByUser(otherOwner.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(theirs).To(HaveLen(1))
		})
	})

	Describe("Touch", func() {
		It("bumps last_used_at", func() {
			ap := &model.AppPassword{UserID: owner.ID, Name: "touchable", NewPassword: "x"}
			Expect(repo.Put(ap)).To(Succeed())

			before, err := repo.Get(ap.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(before.LastUsedAt).To(BeNil())

			Expect(repo.Touch(ap.ID)).To(Succeed())

			after, err := repo.Get(ap.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(after.LastUsedAt).ToNot(BeNil())
		})

		It("does not bump last_used_at on a revoked password (TOCTOU guard)", func() {
			ap := &model.AppPassword{UserID: owner.ID, Name: "revoked-touch", NewPassword: "x"}
			Expect(repo.Put(ap)).To(Succeed())
			Expect(repo.Revoke(ap.ID)).To(Succeed())

			Expect(repo.Touch(ap.ID)).To(Succeed())

			after, err := repo.Get(ap.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(after.LastUsedAt).To(BeNil())
		})
	})
})
