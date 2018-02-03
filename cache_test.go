package introspection_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/srikrsna/oauth-introspection"
)

func TestInMemoryCacheBasic(t *testing.T) {
	c := introspection.NewInMemoryCache()

	res := introspection.Result{Active: true}

	c.Store("key", &res, time.Second)

	equals(t, res, *c.Get("key"))
}

func TestInMemoryCacheExpiry(t *testing.T) {
	c := introspection.NewInMemoryCache()

	res := introspection.Result{Active: true}

	c.Store("key", &res, 2*time.Millisecond)

	time.Sleep(1 * time.Millisecond)

	equals(t, res, *c.Get("key"))

	time.Sleep(2 * time.Millisecond)

	assert(t, c.Get("key") == nil, "key should have expired")
}

func TestInMemoryCacheParallel(t *testing.T) {
	c := introspection.NewInMemoryCache()

	res := introspection.Result{Active: true}

	wg := sync.WaitGroup{}

	wg.Add(10)

	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				c.Store("key", &res, time.Second)
				equals(t, res, *c.Get("key"))
			}
		}()
	}

	wg.Wait()

	equals(t, res, *c.Get("key"))
}

func assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: "+msg+"\033[39m\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
		tb.FailNow()
	}
}

func ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		tb.FailNow()
	}
}

func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}
