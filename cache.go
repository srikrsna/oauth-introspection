package introspection

import (
	"sync"
	"time"
)

// Cache is used to store the introspection result
type Cache interface {
	// Get gets the Result object associated with the key
	Get(key string) *Result

	// Store is used to store an introspection result associated with the key set to expire in specified duration
	Store(key string, res *Result, exp time.Duration)
}

func NewInMemoryCache() Cache {
	return &inMemoryCache{
		results: make(map[string]*Result),
		expiry:  make(map[string]*time.Timer),
	}
}

type inMemoryCache struct {
	sync.RWMutex

	results map[string]*Result
	expiry  map[string]*time.Timer
}

func (mc *inMemoryCache) Get(key string) *Result {
	mc.RLock()
	defer mc.RUnlock()

	return mc.results[key]
}

func (mc *inMemoryCache) Store(key string, res *Result, exp time.Duration) {
	mc.Lock()

	mc.results[key] = res

	if val, ok := mc.expiry[key]; ok {
		val.Stop()
	}

	mc.expiry[key] = time.AfterFunc(exp, func() {
		mc.Lock()
		delete(mc.results, key)
		delete(mc.expiry, key)
		mc.Unlock()
	})

	mc.Unlock()
}
