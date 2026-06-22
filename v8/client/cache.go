package client

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Cache for service tickets held by the client.
type Cache struct {
	Entries map[string]CacheEntry
	mux     sync.RWMutex
}

// CacheEntry holds details for a cache entry.
type CacheEntry struct {
	SPN        string
	Ticket     messages.Ticket `json:"-"`
	AuthTime   time.Time
	StartTime  time.Time
	EndTime    time.Time
	RenewTill  time.Time
	SessionKey types.EncryptionKey `json:"-"`
}

// NewCache creates a new client ticket cache instance.
func NewCache() *Cache {
	return &Cache{
		Entries: map[string]CacheEntry{},
	}
}

// getEntry returns a cache entry that matches the SPN.
func (c *Cache) getEntry(spn string) (CacheEntry, bool) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	e, ok := (*c).Entries[spn]
	return e, ok
}

// JSON returns information about the cached service tickets in a JSON format.
func (c *Cache) JSON() (string, error) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	var es []CacheEntry
	keys := make([]string, 0, len(c.Entries))
	for k := range c.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		es = append(es, c.Entries[k])
	}
	b, err := json.MarshalIndent(&es, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// addEntry adds a ticket to the cache.
func (c *Cache) addEntry(tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey) CacheEntry {
	spn := tkt.SName.PrincipalNameString()
	return c.addEntryWithKey(spn, tkt, authTime, startTime, endTime, renewTill, sessionKey)
}

// addEntryWithKey adds a ticket to the cache using the specified SPN string as the key.
// The provided spn is used as the authoritative cache key regardless of what SName is in the ticket.
func (c *Cache) addEntryWithKey(spn string, tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey) CacheEntry {
	c.mux.Lock()
	defer c.mux.Unlock()
	(*c).Entries[spn] = CacheEntry{
		SPN:        spn,
		Ticket:     tkt,
		AuthTime:   authTime,
		StartTime:  startTime,
		EndTime:    endTime,
		RenewTill:  renewTill,
		SessionKey: sessionKey,
	}
	return c.Entries[spn]
}

// clear deletes all the cache entries
func (c *Cache) clear() {
	c.mux.Lock()
	defer c.mux.Unlock()
	for k := range c.Entries {
		delete(c.Entries, k)
	}
}

// RemoveEntry removes the cache entry for the defined SPN.
func (c *Cache) RemoveEntry(spn string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.Entries, spn)
}

// GetCachedTicket returns a ticket from the cache for the SPN.
// Only a ticket that is currently valid will be returned.
func (cl *Client) GetCachedTicket(spn string) (messages.Ticket, types.EncryptionKey, bool) {
	if e, ok := cl.cache.getEntry(spn); ok {
		//If within time window of ticket return it
		if time.Now().UTC().After(e.StartTime) && time.Now().UTC().Before(e.EndTime) {
			cl.Log("ticket received from cache for %s", spn)
			return e.Ticket, e.SessionKey, true
		} else if time.Now().UTC().Before(e.RenewTill) {
			e, err := cl.renewTicket(spn, e)
			if err != nil {
				return e.Ticket, e.SessionKey, false
			}
			return e.Ticket, e.SessionKey, true
		}
	}
	var tkt messages.Ticket
	var key types.EncryptionKey
	return tkt, key, false
}

// renewTicket renews a cache entry ticket.
// The originalSpn parameter is the authoritative cache key to use when writing the renewed ticket back.
// To renew from outside the client package use GetCachedTicket
func (cl *Client) renewTicket(originalSpn string, e CacheEntry) (CacheEntry, error) {
	spn := e.Ticket.SName
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, e.Ticket.Realm, e.Ticket, e.SessionKey, true)
	if err != nil {
		return e, err
	}
	e = cl.cache.addEntryWithKey(originalSpn, tgsRep.Ticket, tgsRep.DecryptedEncPart.AuthTime, tgsRep.DecryptedEncPart.StartTime, tgsRep.DecryptedEncPart.EndTime, tgsRep.DecryptedEncPart.RenewTill, tgsRep.DecryptedEncPart.Key)
	cl.Log("ticket renewed for %s (EndTime: %v)", originalSpn, e.EndTime)
	return e, nil
}
