package nativeapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
)

// appPasswordSecretBytes is the entropy of a generated app password before
// base64 encoding. 32 bytes = 256 bits, comfortably above any salt+token
// guessing budget.
const appPasswordSecretBytes = 32

// User-app-password endpoints. A user (or an admin) can list, create, and
// revoke app passwords for any user. The plaintext secret is returned only
// once, on creation.
func (api *Router) addAppPasswordRoute(r chi.Router) {
	r.Route("/user/{id}/app-password", func(r chi.Router) {
		r.Use(parseUserIDMiddleware)
		r.Use(appPasswordAccessMiddleware)
		r.Get("/", listAppPasswords(api.ds))
		r.Post("/", createAppPassword(api.ds))
		r.Delete("/", revokeAllAppPasswords(api.ds))
		r.Route("/{appPasswordId}", func(r chi.Router) {
			r.Delete("/", revokeAppPassword(api.ds))
		})
	})
}

// appPasswordAccessMiddleware authorizes the request: the caller must either
// be the user being managed or an admin.
func appPasswordAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := r.Context().Value("userID").(string) //nolint:staticcheck // matches existing parseUserIDMiddleware
		caller, ok := request.UserFrom(r.Context())
		if !ok {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}
		if !caller.IsAdmin && caller.ID != userID {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func listAppPasswords(ds model.DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID := ctx.Value("userID").(string) //nolint:staticcheck

		if _, err := ds.User(ctx).Get(userID); err != nil {
			if errors.Is(err, model.ErrNotFound) {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			log.Error(ctx, "Error loading user", "userID", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		items, err := ds.AppPassword(ctx).List(userID)
		if err != nil {
			log.Error(ctx, "Error listing app passwords", "userID", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if items == nil {
			items = model.AppPasswords{}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(items); err != nil {
			log.Error(ctx, "Error encoding app password list response", err)
		}
	}
}

func createAppPassword(ds model.DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID := ctx.Value("userID").(string) //nolint:staticcheck

		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if body.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}

		if _, err := ds.User(ctx).Get(userID); err != nil {
			if errors.Is(err, model.ErrNotFound) {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			log.Error(ctx, "Error loading user", "userID", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		secret, err := generateAppPasswordSecret()
		if err != nil {
			log.Error(ctx, "Error generating app password secret", "userID", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		ap := &model.AppPassword{
			UserID:      userID,
			Name:        body.Name,
			NewPassword: secret,
		}
		if err := ds.AppPassword(ctx).Put(ap); err != nil {
			log.Error(ctx, "Error creating app password", "userID", userID, "name", body.Name, err)
			http.Error(w, "Failed to create app password", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// Plaintext secret is returned ONCE, here. After this response, the
		// only retrievable form is the encrypted password used by the auth
		// flow itself. (gosec G117 flags any "secret" field in a response;
		// this is the deliberate one-time-display, the rest of the API never
		// exposes it.)
		resp := struct {
			ID        string `json:"id"`
			UserID    string `json:"userId"`
			Name      string `json:"name"`
			Secret    string `json:"secret"` //nolint:gosec // intentional one-time return
			CreatedAt string `json:"createdAt"`
		}{
			ID:        ap.ID,
			UserID:    ap.UserID,
			Name:      ap.Name,
			Secret:    secret,
			CreatedAt: ap.CreatedAt.Format("2006-01-02T15:04:05.000Z"),
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil { //nolint:gosec // Secret field returned by design (one-time display)
			log.Error(ctx, "Error encoding app password create response", err)
		}
	}
}

func revokeAppPassword(ds model.DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID := ctx.Value("userID").(string) //nolint:staticcheck
		appPasswordID := chi.URLParam(r, "appPasswordId")
		if appPasswordID == "" {
			http.Error(w, "Invalid app password ID", http.StatusBadRequest)
			return
		}

		// Make sure the app password belongs to the user from the URL — this
		// prevents an admin from accidentally revoking someone else's app
		// password by hitting /user/$other/app-password/$id.
		ap, err := ds.AppPassword(ctx).Get(appPasswordID)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				http.Error(w, "App password not found", http.StatusNotFound)
				return
			}
			log.Error(ctx, "Error loading app password", "id", appPasswordID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if ap.UserID != userID {
			http.Error(w, "App password not found", http.StatusNotFound)
			return
		}

		if err := ds.AppPassword(ctx).Revoke(appPasswordID); err != nil {
			if errors.Is(err, model.ErrNotFound) {
				http.Error(w, "App password not found", http.StatusNotFound)
				return
			}
			log.Error(ctx, "Error revoking app password", "id", appPasswordID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			ID string `json:"id"`
		}{ID: appPasswordID}); err != nil {
			log.Error(ctx, "Error encoding revoke response", err)
		}
	}
}

func revokeAllAppPasswords(ds model.DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID := ctx.Value("userID").(string) //nolint:staticcheck

		count, err := ds.AppPassword(ctx).RevokeAllForUser(userID)
		if err != nil {
			log.Error(ctx, "Error revoking all app passwords", "userID", userID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			Revoked int64 `json:"revoked"`
		}{Revoked: count}); err != nil {
			log.Error(ctx, "Error encoding revoke-all response", err)
		}
	}
}

// generateAppPasswordSecret returns a URL-safe random secret. The output is
// base64-encoded so it can be pasted into Subsonic clients that don't accept
// arbitrary bytes; the underlying entropy is appPasswordSecretBytes * 8 bits.
func generateAppPasswordSecret() (string, error) {
	buf := make([]byte, appPasswordSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
