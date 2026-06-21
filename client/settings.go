package client

import "log"

// Settings holds optional client settings.
type Settings struct {
	disablePAFXFast         bool
	assumePreAuthentication bool
	preAuthEType            int32
	preAuthRealm            string
	logger                  *log.Logger
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

// clearPreAuth resets the pre-authentication state.
func (s *Settings) clearPreAuth() {
	s.assumePreAuthentication = false
	s.preAuthEType = 0
	s.preAuthRealm = ""
}

// checkPreAuthRealm clears pre-auth state if switching realms.
func (s *Settings) checkPreAuthRealm(realm string) {
	if s.preAuthRealm != "" && s.preAuthRealm != realm {
		s.clearPreAuth()
	}
	s.preAuthRealm = realm
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Printf(format, v...)
	}
}
