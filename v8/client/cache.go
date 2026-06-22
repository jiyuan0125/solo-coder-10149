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

// putEntry is the authoritative (private) store primitive: it writes a
// CacheEntry under the caller-provided SPN key, exactly preserving that key
// as both the map index and the entry's SPN record.
func (c *Cache) putEntry(spnKey string, tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey) CacheEntry {
	c.mux.Lock()
	defer c.mux.Unlock()
	e := CacheEntry{
		SPN:        spnKey,
		Ticket:     tkt,
		AuthTime:   authTime,
		StartTime:  startTime,
		EndTime:    endTime,
		RenewTill:  renewTill,
		SessionKey: sessionKey,
	}
	(*c).Entries[spnKey] = e
	return e
}

// addEntry adds a ticket to the cache, keyed by the ticket's own SName
// string. Use addEntryForSPNKey when a caller-controlled authoritative key
// is required (e.g. renewal paths where the KDC may canonicalise the SName).
func (c *Cache) addEntry(tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey) CacheEntry {
	return c.putEntry(tkt.SName.PrincipalNameString(), tkt, authTime, startTime, endTime, renewTill, sessionKey)
}

// addEntryForSPNKey adds a ticket to the cache using the caller-provided
// SPN string as the authoritative map key, regardless of what SName the
// ticket itself carries. This is required on renewal paths (Bug 3) where
// the key used for the original GetCachedTicket(spn) lookup must match the
// key under which the renewed ticket is written back, even though the KDC
// may return a ticket with a slightly different SName string (case,
// trailing whitespace, realm canonicalisation, etc.).
func (c *Cache) addEntryForSPNKey(spnKey string, tkt messages.Ticket, authTime, startTime, endTime, renewTill time.Time, sessionKey types.EncryptionKey) CacheEntry {
	return c.putEntry(spnKey, tkt, authTime, startTime, endTime, renewTill, sessionKey)
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
			e, err := cl.renewTicket(e, spn)
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

// renewTicket renews a cache entry ticket. The originalSPN argument is the
// *exact* string the caller originally passed into GetCachedTicket — this is
// the authoritative cache key under which the renewed ticket must be written
// back, regardless of any SName canonicalisation the KDC may have applied
// when returning the renewed ticket (Bug 3).
//
// To renew from outside the client package use GetCachedTicket.
func (cl *Client) renewTicket(e CacheEntry, originalSPN string) (CacheEntry, error) {
	reqSPN := e.Ticket.SName
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(reqSPN, e.Ticket.Realm, e.Ticket, e.SessionKey, true)
	if err != nil {
		return e, err
	}
	// Bug 3 fix: explicitly re-write the entry under the *original* lookup
	// key, not whatever SName string the renewed ticket happens to carry.
	// TGSExchange already called addEntry under the KDC-returned SName key;
	// we now mirror the entry under the caller's authoritative key so a
	// subsequent GetCachedTicket(originalSPN) still hits it.
	e = cl.cache.addEntryForSPNKey(
		originalSPN,
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Key,
	)
	cl.Log("ticket renewed for %s (EndTime: %v)", originalSPN, e.EndTime)
	return e, nil
}
