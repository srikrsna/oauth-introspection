package introspection_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srikrsna/oauth-introspection"
)

func TestEndpointFromDiscovery(t *testing.T) {
	ts := openIdServer(t, nil, nil)
	defer ts.Close()

	t.Run("Without Slash", func(t *testing.T) {
		endpoint, err := introspection.EndpointFromDiscovery(ts.URL)

		ok(t, err)

		equals(t, ts.URL+"/introspect", endpoint)
	})

	t.Run("With Slash", func(t *testing.T) {
		endpoint, err := introspection.EndpointFromDiscovery(ts.URL + "/")

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

		introspection.Must(introspection.EndpointFromDiscovery(""))
	})

	t.Run("Wrong Issuer", func(t *testing.T) {
		defer func() {
			err := recover()
			assert(t, err != nil, "should have panicked")
		}()

		introspection.Must(introspection.EndpointFromDiscovery("https://localhost:23455/"))
	})

	ts := openIdServer(t, nil, nil)
	defer ts.Close()

	t.Run("No Error", func(t *testing.T) {
		defer func() {
			err := recover()
			assert(t, err == nil, "error should be nil")
		}()

		equals(t, ts.URL+"/introspect", introspection.Must(introspection.EndpointFromDiscovery(ts.URL)))
	})

	t.Run("Wrong Response Format", func(t *testing.T) {
		defer func() {
			err := recover()
			assert(t, err != nil, "should have panicked")
		}()

		ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "Not Json")
		})

		introspection.Must(introspection.EndpointFromDiscovery(ts.URL))
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

		if !valid(r) {
			err := json.NewEncoder(w).Encode(struct {
				Active bool `json:"active"`
			}{})
			if err != nil {
				tb.Skip(err)
			}

			return
		}

		err := json.NewEncoder(w).Encode(introspectData)
		if err != nil {
			tb.Skip(err)
		}
	})

	return httptest.NewServer(mux)
}
