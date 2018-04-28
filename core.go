package introspection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func introspectionResult(token string, opt Options) (*Result, error) {
	if opt.cache != nil {
		if res := opt.cache.Get(token); res != nil {
			return res, nil
		}
	}

	res, err := introspect(token, &opt)

	if err == nil && opt.cache != nil {
		opt.cache.Store(token, res, opt.cacheExp)
	}

	return res, err
}

func introspect(token string, opt *Options) (*Result, error) {

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

func extractIntrospectResult(r io.Reader) (*Result, error) {
	res := Result{
		Optionals: make(map[string]json.RawMessage),
	}

	if err := json.NewDecoder(r).Decode(&res.Optionals); err != nil {
		return nil, err
	}

	if val, ok := res.Optionals["active"]; ok {
		if err := json.Unmarshal(val, &res.Active); err != nil {
			return nil, err
		}

		delete(res.Optionals, "active")
	}

	return &res, nil
}

// Result is the OAuth2 Introspection Result
type Result struct {
	Active bool

	Optionals map[string]json.RawMessage
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
