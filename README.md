# OAuth2 Introspection

Go middleware client library for the OAuth2 Introspection Spec ([rfc7662](https://tools.ietf.org/html/rfc7662 "Introspection Spec")). Its 100% compatible with standard `net/http`. Can be used with a variety of routers. Built using the new `content` package in Go 1.7 and hence only works for Go 1.7+. Can be easily extended as allowed in the spec. For more advanced examples refer to the [godoc](https://godoc.org/github.com/srikrsna/oauth-introspection).


## Simple Example

```go
package main

import (
    "net/http"
    "fmt"
    
    "github.com/srikrsna/oauth-introspection"
)

func main() {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/secure/ping", func(w http.ResponseWriter, r*http.Request) {
	    res, err := introspection.FromContext(r.Context())
	    if err != nil {
	    	panic(err) // Note: Handle in real code
	    }
	    
	    if !res.Active {
	    	http.Error(w, "Token Invalid", 401)
	    }
	    
	    // Check for Scopes and other values
	    
	    fmt.Fprint(w, "secure pong")
	})
	
	intro := introspection.Introspection(
		introspection.Must(
			introspection.EndpointFromDiscovery("https://auth.example.com"), 
		),
		
		// Add Additional Headers, Form Parameters if needed
	)
	
	http.ListenAndServe(":8080", intro(mux))
}

```
