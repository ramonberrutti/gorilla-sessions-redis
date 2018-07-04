package gsredis

import (
	"encoding/base32"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// NewStore returns a new Store.
//
// The path argument is the directory where sessions will be saved. If empty
// it will use os.TempDir().
//
// See NewCookieStore() for a description of the other parameters.
func NewStore(redis *redis.Client, keyPairs ...[]byte) *Store {
	store := &Store{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			HttpOnly: true,
		},
		redis: redis,
	}

	store.MaxAge(store.Options.MaxAge)
	return store
}

// Store stores sessions in redis.
//
// It also serves as a reference for custom stores.
//
// This store is still experimental and not well tested. Feedback is welcome.
type Store struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
	path    string
	redis   *redis.Client
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new Store is 4096.
func (s *Store) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *Store) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *Store) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil {
			err = s.load(session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *Store) Save(r *http.Request, w http.ResponseWriter,
	session *sessions.Session) error {
	// Delete if max-age is <= 0
	if session.Options.MaxAge <= 0 {
		if err := s.erase(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(32)), "=")
	}
	if err := s.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *Store) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// save writes encoded session.Values to redis.
func (s *Store) save(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
	if err != nil {
		return err
	}

	return s.redis.Set("session:"+session.ID, encoded, time.Duration(int64(s.Options.MaxAge)*int64(time.Second))).Err()
}

// load get key from redis and decodes its content into session.Values.
func (s *Store) load(session *sessions.Session) error {
	ss := s.redis.Get("session:" + session.ID)
	if ss.Err() != nil {
		return ss.Err()
	}

	return securecookie.DecodeMulti(session.Name(), ss.String(),
		&session.Values, s.Codecs...)
}

// delete session key
func (s *Store) erase(session *sessions.Session) error {
	return s.redis.Del("session:" + session.ID).Err()
}
