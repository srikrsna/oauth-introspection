package introspection

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
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

	if iss == "" {
		panic("no issuer passed")
	}

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
	defer res.Body.Close()

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

func makeOptions(endpoint string, opts []Option) Options {
	opt := Options{
		Client: &http.Client{
			Timeout: 2 * time.Second,
		},
		body:   url.Values{"token": {""}, "token_type_hint": {"access_token"}},
		header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Accept": {"application/json"}},

		endpoint: endpoint,
	}

	for _, apply := range opts {
		apply(&opt)
	}

	return opt
}
