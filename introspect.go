package introspection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	discoveryPath = ".well-known/openid-configuration"
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
		Timeout: 1 * time.Second,
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
		Client: &http.Client{},
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
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resKey, &result{Err: errors.New("bearer not found")})))
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

			if err != nil && opt.cache != nil {
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

	if res.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("invalid content-type: expected application/json got %s", res.Header.Get("Content-Type"))
	}

	return extractIntrospectResult(res.Body)
}

func extractIntrospectResult(r io.Reader) (*Result, error) {
	var rlt Result
	var jObj map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&jObj); err != nil {
		return nil, err
	}

	if v, ok := jObj["active"]; ok {
		if err := json.Unmarshal(v, &rlt.Active); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("field 'active' missing from introspection response")
	}

	if v, ok := jObj["scope"]; ok {
		var scopes string
		err := json.Unmarshal(v, &scopes)
		if err != nil {
			return nil, err
		}
		rlt.Scope = strings.Split(scopes, " ")
		delete(jObj, "scope")
	}

	if v, ok := jObj["client_id"]; ok {
		err := json.Unmarshal(v, &rlt.ClientID)
		if err != nil {
			return nil, err
		}
		delete(jObj, "client_id")
	}

	if v, ok := jObj["username"]; ok {
		err := json.Unmarshal(v, &rlt.Username)
		if err != nil {
			return nil, err
		}
		delete(jObj, "username")
	}

	if v, ok := jObj["token_type"]; ok {
		err := json.Unmarshal(v, &rlt.TokenType)
		if err != nil {
			return nil, err
		}
		delete(jObj, "token_type")
	}

	if v, ok := jObj["exp"]; ok {
		err := json.Unmarshal(v, &rlt.EXP)
		if err != nil {
			return nil, err
		}
		delete(jObj, "exp")
	}

	if v, ok := jObj["iat"]; ok {
		err := json.Unmarshal(v, &rlt.IAT)
		if err != nil {
			return nil, err
		}
		delete(jObj, "iat")
	}

	if v, ok := jObj["nbf"]; ok {
		err := json.Unmarshal(v, &rlt.NBF)
		if err != nil {
			return nil, err
		}
		delete(jObj, "nbf")
	}

	if v, ok := jObj["sub"]; ok {
		err := json.Unmarshal(v, &rlt.SUB)
		if err != nil {
			return nil, err
		}
		delete(jObj, "sub")
	}
	if v, ok := jObj["aud"]; ok {
		err := json.Unmarshal(v, &rlt.AUD)
		if err != nil {
			return nil, err
		}
		delete(jObj, "aud")
	}
	if v, ok := jObj["iss"]; ok {
		err := json.Unmarshal(v, &rlt.ISS)
		if err != nil {
			return nil, err
		}
		delete(jObj, "iss")
	}
	if v, ok := jObj["jti"]; ok {
		err := json.Unmarshal(v, &rlt.JTI)
		if err != nil {
			return nil, err
		}
		delete(jObj, "jti")
	}

	rlt.Additional = jObj

	return &rlt, nil
}

// Result is the OAuth2 Introspection Result
type Result struct {
	Active   bool
	Scope    []string
	ClientID string

	Username  string
	TokenType string

	EXP int
	IAT int
	NBF int

	SUB string
	AUD string
	ISS string
	JTI string

	Additional map[string]json.RawMessage
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

	return nil, errors.New("introspection middleware didn't execute")
}
