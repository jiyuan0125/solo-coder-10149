package client

import (
	"fmt"
	"net"

	"gopkg.in/jcmturner/gokrb5.v7/kadmin"
	"gopkg.in/jcmturner/gokrb5.v7/messages"
)

// Kpasswd server response codes.
const (
	KRB5_KPASSWD_SUCCESS             = 0
	KRB5_KPASSWD_MALFORMED           = 1
	KRB5_KPASSWD_HARDERROR           = 2
	KRB5_KPASSWD_AUTHERROR           = 3
	KRB5_KPASSWD_SOFTERROR           = 4
	KRB5_KPASSWD_ACCESSDENIED        = 5
	KRB5_KPASSWD_BAD_VERSION         = 6
	KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
)

// ChangePasswd changes the password of the client to the value provided.
func (cl *Client) ChangePasswd(newPasswd string) (bool, error) {
	// Bug 1: Preserve original credential state so failure / panic paths leave
	// the credentials object untouched. The caller holds the same *Credentials
	// reference before and after this call, so identity must be preserved.
	oldPassword := cl.Credentials.Password()
	oldKeytab := cl.Credentials.Keytab()
	success := false
	defer func() {
		if !success {
			// Roll back: restore password / keytab pointers so any partial
			// mutation (or panic) does not leave credentials half-changed.
			cl.Credentials.WithPassword(oldPassword)
			if oldKeytab != nil && len(oldKeytab.Entries) > 0 {
				// Restore original keytab if caller was using keytab auth
				cl.Credentials.WithKeytab(oldKeytab)
			}
		}
	}()

	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, err
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.ChangePasswdMsg(cl.Credentials.CName(), cl.Credentials.Domain(), newPasswd, ASRep.Ticket, ASRep.DecryptedEncPart.Key)
	if err != nil {
		return false, err
	}
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return false, err
	}
	err = r.Decrypt(key)
	if err != nil {
		return false, err
	}
	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return false, fmt.Errorf("error response from kadmin: code: %d; result: %s; krberror: %v", r.ResultCode, r.Result, r.KRBError)
	}

	// Bug 1: Before mutating credentials, destroy every existing session's
	// auto-renew goroutine (close cancel channels, stop timers) and wipe
	// the ticket cache. Otherwise a 30s TGT renew timer that fires exactly
	// at this moment will take the *new* credentials' TGT/sessionKey and
	// try to renew against a KDC that still sees the *old* session key,
	// corrupting the whole realm state.
	cl.sessions.destroy()
	cl.cache.clear()
	cl.settings.resetPreAuth()

	cl.Credentials.WithPassword(newPasswd)
	success = true
	return true, nil
}

func (cl *Client) sendToKPasswd(msg kadmin.Request) (r kadmin.Reply, err error) {
	_, kps, err := cl.Config.GetKpasswdServers(cl.Credentials.Domain(), true)
	if err != nil {
		return
	}
	addr := kps[1]
	b, err := msg.Marshal()
	if err != nil {
		return
	}
	// Bug 5: Symmetric behaviour to sendToKDC — handle limit<=0 (TCP-first),
	// then limit==1 (force-TCP sentinel), then normal size-based choice.
	limit := cl.Config.LibDefaults.UDPPreferenceLimit
	if limit <= 0 {
		r, err = cl.sendKPasswdTCP(b, addr)
		if err != nil {
			return cl.sendKPasswdUDP(b, addr)
		}
		return
	}
	if limit == 1 {
		return cl.sendKPasswdTCP(b, addr)
	}
	if len(b) <= limit {
		return cl.sendKPasswdUDP(b, addr)
	}
	return cl.sendKPasswdTCP(b, addr)
}

func (cl *Client) sendKPasswdTCP(b []byte, kadmindAddr string) (r kadmin.Reply, err error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", kadmindAddr)
	if err != nil {
		return
	}
	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return
	}
	rb, err := cl.sendTCP(conn, b)
	if err != nil {
		return
	}
	err = r.Unmarshal(rb)
	return
}

func (cl *Client) sendKPasswdUDP(b []byte, kadmindAddr string) (r kadmin.Reply, err error) {
	udpAddr, err := net.ResolveUDPAddr("udp", kadmindAddr)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return
	}
	rb, err := cl.sendUDP(conn, b)
	if err != nil {
		return
	}
	err = r.Unmarshal(rb)
	return
}
