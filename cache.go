package certexpire

import (
	"sync"
)

// Cache caches call results.
type Cache struct {
	cache map[string]*cacheObject
	lock  *sync.Mutex
}

type cacheObject struct {
	result  interface{}
	futures []chan interface{}
	lock    *sync.Mutex
}

// NewCache creates a new cache.
func NewCache() *Cache {
	r := &Cache{
		cache: make(map[string]*cacheObject),
		lock:  new(sync.Mutex),
	}
	return r
}

func (c *Cache) register(key string, value interface{}) {
	e := c.lookup(key)
	if e != nil {
		e.lock.Lock()
		defer e.lock.Unlock()
		e.result = value
		for _, c := range e.futures {
			c <- value
			close(c)
		}
	}
}

func (c *Cache) lookup(key string) *cacheObject {
	c.lock.Lock()
	defer c.lock.Unlock()
	if e, ok := c.cache[key]; ok {
		return e
	}
	return nil
}

// Lookup checks for the cached object. If none is found, the factory will be called. Returns a channel to receive the result from.
func (c *Cache) Lookup(key string, factory func() interface{}) chan interface{} {
	c.lock.Lock()
	rchan := make(chan interface{}, 1) // Return results.
	// Check if we know the key.
	if e, ok := c.cache[key]; ok {
		e.lock.Lock() // Switch lock to element mutex
		defer e.lock.Unlock()
		c.lock.Unlock()

		if e.result != nil { // We have a result.
			rchan <- e.result
			close(rchan)
		} else {
			e.futures = append(e.futures, rchan)
		}
	} else {
		t := &cacheObject{
			futures: []chan interface{}{rchan},
			lock:    new(sync.Mutex),
		}
		c.cache[key] = t
		c.lock.Unlock()
		// Call factory
		go func() {
			value := factory()
			c.register(key, value)
		}()
	}
	return rchan
}
