package client

import (
	"fmt"

	"github.com/jcmturner/gokrb5/v8/kadmin"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
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
	oldPassword := cl.Credentials.Password()
	var oldKeytab *keytab.Keytab
	if cl.Credentials.HasKeytab() {
		oldKeytab = cl.Credentials.Keytab()
	}
	success := false
	defer func() {
		if !success {
			if oldKeytab != nil {
				cl.Credentials.WithKeytab(oldKeytab)
			}
			if oldPassword != "" {
				cl.Credentials.WithPassword(oldPassword)
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
	b, err := msg.Marshal()
	if err != nil {
		return
	}
	limit := cl.Config.LibDefaults.UDPPreferenceLimit
	var rb []byte
	if limit <= 0 {
		rb, err = dialSendTCP(kps, b)
		if err != nil {
			rb, err = dialSendUDP(kps, b)
			if err != nil {
				return
			}
		}
	} else if limit == 1 {
		rb, err = dialSendTCP(kps, b)
		if err != nil {
			return
		}
	} else if len(b) <= limit {
		rb, err = dialSendUDP(kps, b)
		if err != nil {
			return
		}
	} else {
		rb, err = dialSendTCP(kps, b)
		if err != nil {
			return
		}
	}
	err = r.Unmarshal(rb)
	return
}
