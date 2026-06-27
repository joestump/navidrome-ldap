package subsonic

import (
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	ua "github.com/mileusna/useragent"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/core/metrics"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/server"
	"github.com/navidrome/navidrome/server/subsonic/responses"
	. "github.com/navidrome/navidrome/utils/gg"
	"github.com/navidrome/navidrome/utils/req"
)

func postFormToQueryParams(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB
		err := r.ParseForm()
		if err != nil {
			sendError(w, r, newError(responses.ErrorGeneric, err.Error()))
			return
		}
		var parts []string
		for key, values := range r.Form {
			for _, v := range values {
				parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(v))
			}
		}
		r.URL.RawQuery = strings.Join(parts, "&")

		next.ServeHTTP(w, r)
	})
}

func fromInternalOrProxyAuth(r *http.Request) (string, bool) {
	username := server.InternalAuth(r)

	// If the username comes from internal auth, do not also do reverse proxy auth, as
	// the request will have no reverse proxy IP
	if username != "" {
		return username, true
	}

	return server.UsernameFromExtAuthHeader(r), false
}

func checkRequiredParameters(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requiredParameters []string

		username, _ := fromInternalOrProxyAuth(r)
		if username != "" {
			requiredParameters = []string{"v", "c"}
		} else {
			requiredParameters = []string{"u", "v", "c"}
		}

		p := req.Params(r)
		for _, param := range requiredParameters {
			if _, err := p.String(param); err != nil {
				log.Warn(r, err)
				sendError(w, r, err)
				return
			}
		}

		if username == "" {
			username, _ = p.String("u")
		}
		client, _ := p.String("c")
		version, _ := p.String("v")

		ctx := r.Context()
		ctx = request.WithUsername(ctx, username)
		ctx = request.WithClient(ctx, client)
		ctx = request.WithVersion(ctx, version)
		log.Debug(ctx, "API: New request "+r.URL.Path, "username", username, "client", client, "version", version)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authenticate(ds model.DataStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var usr *model.User
			var err error

			username, isInternalAuth := fromInternalOrProxyAuth(r)
			if username != "" {
				authType := If(isInternalAuth, "internal", "reverse-proxy")
				usr, err = ds.User(ctx).FindByUsername(username)
				if errors.Is(err, context.Canceled) {
					log.Debug(ctx, "API: Request canceled when authenticating", "auth", authType, "username", username, "remoteAddr", r.RemoteAddr, err)
					return
				}
				if errors.Is(err, model.ErrNotFound) {
					log.Warn(ctx, "API: Invalid login", "auth", authType, "username", username, "remoteAddr", r.RemoteAddr, err)
				} else if err != nil {
					log.Error(ctx, "API: Error authenticating username", "auth", authType, "username", username, "remoteAddr", r.RemoteAddr, err)
				}
			} else {
				p := req.Params(r)
				username, _ := p.String("u")
				pass, _ := p.String("p")
				if strings.HasPrefix(pass, "enc:") {
					if dec, err := hex.DecodeString(pass[4:]); err == nil {
						pass = string(dec)
					}
				}
				token, _ := p.String("t")
				salt, _ := p.String("s")
				jwt, _ := p.String("jwt")

				// App-password fast path. When the request carries a `p` or
				// salt+token, try matching against the user's active app
				// passwords FIRST. This avoids hitting LDAP on every Subsonic
				// request from a client using an app password — which is the
				// whole point of decoupling Subsonic auth from the directory.
				// LDAP deployments with lockout policies (AD lockoutThreshold,
				// FreeIPA password policy) would otherwise lock the user's
				// directory account on every legitimate app-password request.
				//
				// We also use this lookup to enforce the LDAP-no-direct-password
				// policy: an LDAP-backed user MUST authenticate with an app
				// password — their directory password is no longer accepted at
				// /rest, even via legacy `p=` or salt+token, since it would
				// otherwise still be checkable via the LDAP bind in
				// `ValidateLogin` and persist the directory password problem.
				if jwt == "" && (pass != "" || token != "") {
					lookupUsr, appID, ok := matchAppPassword(ctx, ds, username, pass, token, salt)
					if ok {
						if touchErr := ds.AppPassword(ctx).Touch(appID); touchErr != nil {
							log.Warn(ctx, "API: Failed to bump app password last_used_at", "id", appID, "username", username, touchErr)
						}
						ctx = request.WithUser(ctx, *lookupUsr)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					if lookupUsr != nil && lookupUsr.IsLDAP() {
						log.Warn(ctx, "API: Rejecting non-app-password Subsonic auth for LDAP user", "username", username, "remoteAddr", r.RemoteAddr)
						sendError(w, r, newError(responses.ErrorAuthenticationFail))
						return
					}
				}

				if pass != "" {
					usr, err = server.ValidateLogin(ds.User(ctx), username, pass)
					if err == nil && usr == nil {
						err = model.ErrNotFound
					}
				} else {
					usr, err = ds.User(ctx).FindByUsernameWithPassword(username)
				}

				if errors.Is(err, context.Canceled) {
					log.Debug(ctx, "API: Request canceled when authenticating", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr, err)
					return
				}
				switch {
				case errors.Is(err, model.ErrNotFound):
					log.Warn(ctx, "API: Invalid login", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr, err)
				case err != nil:
					log.Error(ctx, "API: Error authenticating username", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr, err)
				default:
					if pass == "" {
						err = validateCredentials(usr, pass, token, salt, jwt)
						if err != nil {
							log.Warn(ctx, "API: Invalid login", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr, err)
						}
					}
				}
			}

			if err != nil {
				sendError(w, r, newError(responses.ErrorAuthenticationFail))
				return
			}

			ctx = request.WithUser(ctx, *usr)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggedUser, ok := request.UserFrom(r.Context())
		if !ok {
			sendError(w, r, newError(responses.ErrorGeneric, "Internal error"))
			return
		}

		if !loggedUser.IsAdmin {
			sendError(w, r, newError(responses.ErrorAuthorizationFail))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func validateCredentials(user *model.User, pass, token, salt, jwt string) error {
	valid := false

	switch {
	case jwt != "":
		claims, err := auth.Validate(jwt)
		valid = err == nil && claims.Subject == user.UserName
	case pass != "":
		if strings.HasPrefix(pass, "enc:") {
			if dec, err := hex.DecodeString(pass[4:]); err == nil {
				pass = string(dec)
			}
		}
		// Empty stored password (LDAP users post-ClearPassword, mid-migration
		// rows, etc.) must never be a valid credential — the comparison
		// `"" == ""` would otherwise succeed.
		valid = pass != "" && user.Password != "" && pass == user.Password
	case token != "":
		if user.Password == "" {
			break
		}
		t := fmt.Sprintf("%x", md5.Sum([]byte(user.Password+salt)))
		valid = t == token
	}

	if !valid {
		return model.ErrInvalidAuth
	}
	return nil
}

// matchAppPassword tries to authenticate the request against the user's
// active app passwords. Returns:
//   - (user, appID, true)  on a match
//   - (user, "",   false)  when the user exists but no app password matched
//     (so the caller can decide whether to fall through or reject — the
//     LDAP-user-must-use-app-password gate uses this case)
//   - (nil,  "",   false)  when the user doesn't exist or lookup failed
//
// `pass` MUST already be the decoded plaintext (the parent `authenticate`
// flow handles `enc:` decoding once); we do not decode again.
func matchAppPassword(ctx context.Context, ds model.DataStore, username, pass, token, salt string) (*model.User, string, bool) {
	if username == "" {
		return nil, "", false
	}
	usr, err := ds.User(ctx).FindByUsername(username)
	if err != nil {
		return nil, "", false
	}
	active, err := ds.AppPassword(ctx).FindActiveByUser(usr.ID)
	if err != nil {
		log.Warn(ctx, "API: Error loading app passwords", "username", username, err)
		return usr, "", false
	}
	for _, ap := range active {
		switch {
		case pass != "" && pass == ap.Password:
			return usr, ap.ID, true
		case token != "" && fmt.Sprintf("%x", md5.Sum([]byte(ap.Password+salt))) == token:
			return usr, ap.ID, true
		}
	}
	return usr, "", false
}

func getPlayer(players core.Players) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userName, _ := request.UsernameFrom(ctx)
			client, _ := request.ClientFrom(ctx)
			playerId := playerIDFromCookie(r, userName)
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			userAgent := canonicalUserAgent(r)
			player, trc, err := players.Register(ctx, playerId, client, userAgent, ip)
			if err != nil {
				log.Error(ctx, "Could not register player", "username", userName, "client", client, err)
			} else {
				ctx = request.WithPlayer(ctx, *player)
				if trc != nil {
					ctx = request.WithTranscoding(ctx, *trc)
				}
				r = r.WithContext(ctx)

				cookie := &http.Cookie{ //nolint:gosec // Secure omitted: Navidrome may run over plain HTTP
					Name:     playerIDCookieName(userName),
					Value:    player.ID,
					MaxAge:   consts.CookieExpiry,
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Path:     cmp.Or(conf.Server.BasePath, "/"),
				}
				http.SetCookie(w, cookie)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func canonicalUserAgent(r *http.Request) string {
	u := ua.Parse(r.Header.Get("user-agent"))
	userAgent := u.Name
	if u.OS != "" {
		userAgent = userAgent + "/" + u.OS
	}
	return userAgent
}

func playerIDFromCookie(r *http.Request, userName string) string {
	cookieName := playerIDCookieName(userName)
	var playerId string
	if c, err := r.Cookie(cookieName); err == nil {
		playerId = c.Value
		log.Trace(r, "playerId found in cookies", "playerId", playerId)
	}
	return playerId
}

func playerIDCookieName(userName string) string {
	cookieName := fmt.Sprintf("nd-player-%x", userName)
	return cookieName
}

type contextKey string

const subsonicErrorPointer contextKey = "subsonicErrorPointer"

func recordStats(metrics metrics.Metrics) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			status := int32(-1)
			contextWithStatus := context.WithValue(r.Context(), subsonicErrorPointer, &status)

			start := time.Now()
			defer func() {
				elapsed := time.Since(start).Milliseconds()

				// We want to get the client name (even if not present for certain endpoints)
				p := req.Params(r)
				client, _ := p.String("c")

				// If there is no Subsonic status (e.g., HTTP 501 not implemented), fallback to HTTP
				if status == -1 {
					status = int32(ww.Status())
				}

				shortPath := strings.Replace(r.URL.Path, ".view", "", 1)

				metrics.RecordRequest(r.Context(), shortPath, r.Method, client, status, elapsed)
			}()

			next.ServeHTTP(ww, r.WithContext(contextWithStatus))
		}
		return http.HandlerFunc(fn)
	}
}
