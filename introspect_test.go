package introspection_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	intro "github.com/srikrsna/oauth-introspection"
)

func TestIntrospection(t *testing.T) {

	baseValid := func(t *testing.T, r *http.Request) string {
		equals(t, "POST", r.Method)
		equals(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		return r.PostFormValue("token")
	}

	tt := []struct {
		name    string
		valid   func(t *testing.T) func(r *http.Request) bool
		token   string
		data    map[string]interface{}
		handler func(t *testing.T) func(w http.ResponseWriter, r *http.Request)
		options []intro.Option
	}{
		{
			name:  "Required Response Fields Present Active True",
			token: "random-super-secret-token",
			valid: func(t *testing.T) func(r *http.Request) bool {
				return func(r *http.Request) bool {

					token := baseValid(t, r)

					equals(t, "random-super-secret-token", token)

					return true
				}
			},

			handler: func(t *testing.T) func(w http.ResponseWriter, r *http.Request) {
				return func(w http.ResponseWriter, r *http.Request) {
					res, err := intro.FromContext(r.Context())

					ok(t, err)

					equals(t, true, res.Active)
				}
			},
		},
		{
			name: "Required Response Fields Present Active False",

			token: "random-super-secret-token",
			valid: func(t *testing.T) func(r *http.Request) bool {
				return func(r *http.Request) bool {
					return false
				}
			},

			handler: func(t *testing.T) func(w http.ResponseWriter, r *http.Request) {
				return func(w http.ResponseWriter, r *http.Request) {
					res, err := intro.FromContext(r.Context())

					ok(t, err)

					equals(t, false, res.Active)
				}
			},
		},
		{
			name:  "Additional Fields",
			token: "random-super-secret-token",
			valid: func(t *testing.T) func(r *http.Request) bool {
				return func(r *http.Request) bool {

					token := baseValid(t, r)

					equals(t, "random-super-secret-token", token)

					return true
				}
			},

			handler: func(t *testing.T) func(w http.ResponseWriter, r *http.Request) {
				return func(w http.ResponseWriter, r *http.Request) {
					res, err := intro.FromContext(r.Context())

					ok(t, err)

					equals(t, true, res.Active)

					var role struct {
						Role string `json:"role"`
					}

					json.Unmarshal(res.Optionals["additional"], &role)

					equals(t, "admin", role.Role)
				}
			},
			data: map[string]interface{}{
				"additional": struct {
					Role string `json:"role"`
				}{
					"admin",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ts := openIdServer(t, tc.valid(t), tc.data)
			defer ts.Close()

			if tc.options == nil {
				tc.options = []intro.Option{}
			}

			handler := intro.Introspection(
				intro.Must(intro.EndpointFromDiscovery(ts.URL)),
				tc.options...,
			)(http.HandlerFunc(tc.handler(t)))

			req, res := httptest.NewRequest("GET", "/", nil), httptest.NewRecorder()
			req.Header.Add("Authorization", "Bearer "+tc.token)

			handler.ServeHTTP(res, req)
		})
	}
}

func TestWithCache(t *testing.T) {
	ts := openIdServer(t, nil, nil)
	defer ts.Close()

	var hits int

	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			t.Skip("path should be /introspect check tests")
		}

		equals(t, "POST", r.Method)

		hits++

		w.Header().Add("Content-Type", "application/json")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true,
		})
	})

	req, res := httptest.NewRequest("GET", "/", nil), httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+"token")

	handler := intro.Introspection(
		ts.URL+"/introspect",
		intro.WithCache(intro.NewInMemoryCache(), time.Second),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := intro.FromContext(r.Context())

		ok(t, err)

		equals(t, true, res.Active)
	}))

	for i := 0; i < 10; i++ {
		handler.ServeHTTP(res, req)
	}

	assert(t, hits == 1, fmt.Sprintf("Cache Not Being Used Multiple Hits: %d", hits))
}

func TestWithAddedHeaders(t *testing.T) {
	ts := openIdServer(t, nil, nil)
	defer ts.Close()

	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		equals(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		equals(t, "application/json", r.Header.Get("Accept"))

		username, password, ok := r.BasicAuth()

		assert(t, ok, "basic header should be present")

		equals(t, "hell", username)
		equals(t, "yeah", password)

		w.Header().Add("Content-Type", "application/json")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true,
		})
	})

	req, res := httptest.NewRequest("GET", "/", nil), httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+"token")

	handler := intro.Introspection(
		ts.URL+"/introspect",
		intro.WithAddedHeaders(http.Header{
			"Authorization": {
				fmt.Sprintf("Basic %s", base64.RawStdEncoding.EncodeToString([]byte("hell:yeah"))),
			},
			"Content-Type": {"text/plain"},
			"Accept":       {"text/plain"},
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := intro.FromContext(r.Context())

		ok(t, err)

		equals(t, true, res.Active)
	}))

	handler.ServeHTTP(res, req)
}

func TestWithAddedBody(t *testing.T) {
	ts := openIdServer(t, nil, nil)
	defer ts.Close()

	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Add("Content-Type", "application/json")

		equals(t, "hell", r.PostFormValue("api"))
		equals(t, "yeah", r.PostFormValue("api_secret"))

		equals(t, "token", r.PostFormValue("token"))
		equals(t, "access_token", r.PostFormValue("token_type_hint"))

		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": true,
		})
	})

	req, res := httptest.NewRequest("GET", "/", nil), httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer "+"token")

	handler := intro.Introspection(
		ts.URL+"/introspect",
		intro.WithAddedBody(url.Values{
			"api":        {"hell"},
			"api_secret": {"yeah"},

			"token":           {"wrong-token"},
			"token_type_hint": {"refresh_token"},
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := intro.FromContext(r.Context())

		ok(t, err)

		equals(t, true, res.Active)
	}))

	handler.ServeHTTP(res, req)
}

func TestEndpointFromDiscovery(t *testing.T) {
	ts := openIdServer(t, nil, nil)
	defer ts.Close()

	t.Run("Without Slash", func(t *testing.T) {
		endpoint, err := intro.EndpointFromDiscovery(ts.URL)

		ok(t, err)

		equals(t, ts.URL+"/introspect", endpoint)
	})

	t.Run("With Slash", func(t *testing.T) {
		endpoint, err := intro.EndpointFromDiscovery(ts.URL + "/")

		ok(t, err)

		equals(t, ts.URL+"/introspect", endpoint)
	})
}

func TestMust(t *testing.T) {
	t.Run("Nil Issuer", func(t *testing.T) {
		defer func() {
			err := recover()
			assert(t, err != nil, "should have panicked")
		}()

		intro.Must(intro.EndpointFromDiscovery(""))
	})

	t.Run("Wrong Issuer", func(t *testing.T) {
		defer func() {
			err := recover()
			assert(t, err != nil, "should have panicked")
		}()

		intro.Must(intro.EndpointFromDiscovery("https://localhost:23455/"))
	})

	ts := openIdServer(t, nil, nil)
	defer ts.Close()

	t.Run("No Error", func(t *testing.T) {
		defer func() {
			err := recover()
			assert(t, err == nil, "error should be nil")
		}()

		equals(t, ts.URL+"/introspect", intro.Must(intro.EndpointFromDiscovery(ts.URL)))
	})

	t.Run("Wrong Response Format", func(t *testing.T) {
		defer func() {
			err := recover()
			assert(t, err != nil, "should have panicked")
		}()

		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "Not Json")
		})

		intro.Must(intro.EndpointFromDiscovery(ts.URL))
	})
}

func openIdServer(tb testing.TB, valid func(r *http.Request) bool, introspectData map[string]interface{}) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		res := struct {
			IntrospectionEndpoint string `json:"introspection_endpoint"`
			AuthorizationEndpoint string `json:"authorization_endpoint"`
		}{
			fmt.Sprintf("http://%s%s", r.Host, "/introspect"),
			fmt.Sprintf("http://%s%s", r.Host, "/authorize"),
		}

		err := json.NewEncoder(w).Encode(res)
		if err != nil {
			tb.Skip(err)
		}
	})

	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")

		if !valid(r) {
			err := json.NewEncoder(w).Encode(struct {
				Active bool `json:"active"`
			}{})
			if err != nil {
				tb.Skip(err)
			}

			return
		}

		if introspectData == nil {
			introspectData = make(map[string]interface{})
		}

		introspectData["active"] = true

		err := json.NewEncoder(w).Encode(introspectData)
		if err != nil {
			tb.Skip(err)
		}
	})

	return httptest.NewServer(mux)
}

func TestErrorPropagation(t *testing.T) {
	t.Run("No Bearer", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := intro.FromContext(r.Context())

			equals(t, intro.ErrNoBearer, err)

			assert(t, res == nil, "response should be nil when err is non-nil")
		})

		intro.Introspection("/introspect")(handler).ServeHTTP(nil, httptest.NewRequest("GET", "/", nil))
	})

	t.Run("Server Unavailable", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := intro.FromContext(r.Context())

			assert(t, err != nil, "err should not be nil because of invalid introspection endpoint")

			assert(t, res == nil, "response should be nil when err is non-nil")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Add("Authorization", "Bearer token")

		intro.Introspection("/introspect")(handler).ServeHTTP(nil, req)
	})

	t.Run("Invalid Request", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := intro.FromContext(r.Context())

			assert(t, err != nil, "err should not be nil because of invalid introspection endpoint")

			assert(t, res == nil, "response should be nil when err is non-nil")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Add("Authorization", "Bearer token")

		intro.Introspection("wrong$$$::///asd/introspect")(handler).ServeHTTP(nil, req)
	})

	t.Run("Bad Request", func(t *testing.T) {
		ts := openIdServer(t, nil, nil)
		defer ts.Close()

		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			fmt.Fprint(w, "Basic Header is Missing")
		})

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := intro.FromContext(r.Context())

			assert(t, err != nil, "err should not be nil because of invalid introspection endpoint")

			assert(t, res == nil, "response should be nil when err is non-nil")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Add("Authorization", "Bearer token")

		intro.Introspection(ts.URL+"/introspect")(handler).ServeHTTP(nil, req)
	})

	t.Run("Wrong Data", func(t *testing.T) {
		ts := openIdServer(t, nil, nil)
		defer ts.Close()

		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "NOT JSON")
		})

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := intro.FromContext(r.Context())

			assert(t, err != nil, "err should not be nil because of invalid introspection endpoint")

			assert(t, res == nil, "response should be nil when err is non-nil")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Add("Authorization", "Bearer token")

		intro.Introspection(ts.URL+"/introspect")(handler).ServeHTTP(nil, req)
	})

	t.Run("Wrong Structured Data", func(t *testing.T) {
		ts := openIdServer(t, nil, nil)
		defer ts.Close()

		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"active":"not bool"}`)
		})

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := intro.FromContext(r.Context())

			assert(t, err != nil, "err should not be nil because of invalid introspection endpoint")

			assert(t, res == nil, "response should be nil when err is non-nil")
		})

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Add("Authorization", "Bearer token")

		intro.Introspection(ts.URL+"/introspect")(handler).ServeHTTP(nil, req)
	})

	t.Run("No Middleware", func(t *testing.T) {
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, err := intro.FromContext(r.Context())

			equals(t, intro.ErrNoMiddleware, err)

			assert(t, res == nil, "response should be nil when err is non-nil")
		}).ServeHTTP(nil, httptest.NewRequest("GET", "/", nil))
	})
}
