package mcpauth

import (
	"container/list"
	"sync"
	"time"
)

type CachedToken struct {
	AccessToken string
	TokenType   string
	Audience    string
	ExpiresAt   time.Time
	Scopes      []string
}
type tokenEntry struct {
	key   string
	value CachedToken
}
type TokenCache struct {
	mu     sync.Mutex
	max    int
	margin time.Duration
	values map[string]*list.Element
	order  *list.List
}

func NewTokenCache(maxEntries int, expiryMargin time.Duration) *TokenCache {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &TokenCache{max: maxEntries, margin: expiryMargin, values: map[string]*list.Element{}, order: list.New()}
}
func (c *TokenCache) Get(key string) (CachedToken, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.values[key]
	if !ok {
		return CachedToken{}, false
	}
	entry := element.Value.(tokenEntry)
	if time.Now().Add(c.margin).After(entry.value.ExpiresAt) {
		delete(c.values, key)
		c.order.Remove(element)
		return CachedToken{}, false
	}
	c.order.MoveToFront(element)
	return entry.value, true
}
func (c *TokenCache) Put(key string, value CachedToken) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.values[key]; ok {
		existing.Value = tokenEntry{key, value}
		c.order.MoveToFront(existing)
	} else {
		c.values[key] = c.order.PushFront(tokenEntry{key, value})
	}
	for len(c.values) > c.max {
		oldest := c.order.Back()
		entry := oldest.Value.(tokenEntry)
		delete(c.values, entry.key)
		c.order.Remove(oldest)
	}
}
func (c *TokenCache) Len() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.values) }
