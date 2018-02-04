package introspection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	discoveryPath = ".well-known/openid-configuration"
)

var (
	// ErrNoBearer is returned by FromContext function when no Bearer token was present
	ErrNoBearer = errors.New("no bearer")
	// ErrNoMiddleware is returned by FromContext when no value was set. It is due to the middleware not being called before this function.
	ErrNoMiddleware = errors.New("introspection middleware didn't execute")
)

// Options ...
type Options struct {
	body   url.Values
	header http.Header

	endpoint string
	Client   *http.Client

	cache    Cache
	cacheExp time.Duration
}

// Option ...
type Option func(*Options)

// WithAddedHeaders ...
func WithAddedHeaders(h http.Header) Option {
	return func(opt *Options) {
		for k, v := range h {
			if _, ok := opt.header[k]; !ok {
				opt.header[k] = v
			}
		}
	}
}

// WithAddedBody ...
func WithAddedBody(b url.Values) Option {
	return func(opt *Options) {
		for k, v := range b {
			if _, ok := opt.body[k]; !ok {
				opt.body[k] = v
			}
		}
	}
}

// WithCache uses provided cache to store and retrieve objects, if this option is passed caching will be used otherwise not used
// exp is the expiry for each cache entry
func WithCache(cache Cache, exp time.Duration) Option {
	return func(opt *Options) {
		opt.cache = cache
		opt.cacheExp = exp
	}
}

// EndpointFromDiscovery is helper function to get the introspection endpoint from the openid issuer/authority
func EndpointFromDiscovery(iss string) (string, error) {
	if iss[len(iss)-1] != '/' {
		iss += "/"
	}

	discoveryURI := iss + discoveryPath

	client := http.Client{
		Timeout: 10 * time.Second,
	}

	res, err := client.Get(discoveryURI)
	if err != nil {
		return "", err
	}

	var discoResp struct {
		IntrospectionEndpoint string `json:"introspection_endpoint"`
	}

	if err := json.NewDecoder(res.Body).Decode(&discoResp); err != nil {
		return "", err
	}

	return discoResp.IntrospectionEndpoint, nil
}

// Must is a helper function that panics if err != nil and returns v if err == nil.
// Typical use case is to wrap it with EndpointFromDiscovery function
func Must(v string, err error) string {
	if err != nil {
		panic(err)
	}
	return v
}

// Introspection ...
func Introspection(endpoint string, opts ...Option) func(http.Handler) http.Handler {

	opt := &Options{
		Client: &http.Client{
			Timeout: 2 * time.Second,
		},
		body:   url.Values{"token": {""}, "token_type_hint": {"access_token"}},
		header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}},

		endpoint: endpoint,
	}

	for _, apply := range opts {
		apply(opt)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hd := r.Header.Get("Authorization")

			if !strings.HasPrefix(hd, "Bearer ") {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resKey, &result{Err: ErrNoBearer})))
				return
			}

			token := hd[len("Bearer "):]

			if opt.cache != nil {
				if res := opt.cache.Get(token); res != nil {
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resKey, &result{res, nil})))
					return
				}
			}

			res, err := introspect(token, *opt)

			if err == nil && opt.cache != nil {
				opt.cache.Store(token, res, opt.cacheExp)
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resKey, &result{res, err})))
		})
	}
}

func introspect(token string, opt Options) (*Result, error) {

	body := make(url.Values, len(opt.body))

	for k, v := range opt.body {
		body[k] = v
	}

	body.Set("token", token)

	req, err := http.NewRequest("POST", opt.endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = opt.header

	res, err := opt.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("status does not indicate success: code: %d, body: %v", res.StatusCode, res.Body)
	}

	return extractIntrospectResult(res.Body)
}

var buffPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func extractIntrospectResult(r io.Reader) (*Result, error) {
	buff := buffPool.Get().(*bytes.Buffer)
	buff.Reset()

	r = io.TeeReader(r, buff)

	var all map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&all); err != nil {
		return nil, err
	}

	var rlt Result
	if err := json.NewDecoder(buff).Decode(&rlt); err != nil {
		return nil, err
	}

	buffPool.Put(buff)

	rlt.All = all

	return &rlt, nil
}

// Result is the OAuth2 Introspection Result
type Result struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`

	Username  string `json:"username"`
	TokenType string `json:"token_type"`

	EXP int `json:"exp"`
	IAT int `json:"iat"`
	NBF int `json:"nbf"`

	SUB string   `json:"sub"`
	AUD []string `json:"aud"`
	ISS string   `json:"iss"`
	JTI string   `json:"jti"`

	All map[string]json.RawMessage `json:"-"`
}

type resKeyType int

const resKey = resKeyType(1)

type result struct {
	Result *Result
	Err    error
}

// FromContext ...
func FromContext(ctx context.Context) (*Result, error) {
	if val, ok := ctx.Value(resKey).(*result); ok {
		return val.Result, val.Err
	}

	return nil, ErrNoMiddleware
}
