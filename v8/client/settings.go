package client

import (
	"encoding/json"
	"fmt"
	"log"
)

// Settings holds optional client settings.
type Settings struct {
	disablePAFXFast         bool
	assumePreAuthentication bool
	preAuthEType            int32
	preAuthRealm            string
	logger                  *log.Logger
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	DisablePAFXFast         bool
	AssumePreAuthentication bool
}

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := new(Settings)
	for _, set := range settings {
		set(s)
	}
	return s
}

// DisablePAFXFAST used to configure the client to not use PA_FX_FAST.
//
// s := NewSettings(DisablePAFXFAST(true))
func DisablePAFXFAST(b bool) func(*Settings) {
	return func(s *Settings) {
		s.disablePAFXFast = b
	}
}

// DisablePAFXFAST indicates is the client should disable the use of PA_FX_FAST.
func (s *Settings) DisablePAFXFAST() bool {
	return s.disablePAFXFast
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true))
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication = b
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		DisablePAFXFast:         s.disablePAFXFast,
		AssumePreAuthentication: s.assumePreAuthentication,
	}
	b, err := json.MarshalIndent(&js, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil

}

// resetPreAuthCache clears the pre-authentication cache (etype and realm).
func (s *Settings) resetPreAuthCache() {
	s.preAuthEType = 0
	s.preAuthRealm = ""
}

// checkPreAuthRealm checks if the pre-auth cache is valid for the given realm.
// If we have a cached etype but the realm does not match (including the first time
// entering a new realm with no preAuthRealm recorded), the cache is reset.
func (s *Settings) checkPreAuthRealm(realm string) {
	if s.preAuthEType != 0 && s.preAuthRealm != realm {
		s.resetPreAuthCache()
	}
	s.preAuthRealm = realm
}
