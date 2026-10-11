package htaccess

import (
	"net/http"
	"regexp"
	"strings"
)

// RequestAttrs are the request attributes mod_setenvif matches against, so
// "env=" conditions in access rules (Deny/Allow from env=X, Require env X)
// can be decided for one request. A nil *RequestAttrs means they are unknown
// and every env condition fails closed.
type RequestAttrs struct {
	RemoteAddr string      // client IP, no port (Remote_Addr / Remote_Host)
	Method     string      // Request_Method
	URI        string      // request path (Request_URI)
	Proto      string      // Request_Protocol
	Host       string      // Host header value
	Header     http.Header // any other attribute names are request headers
}

// envState is the set of environment variables SetEnvIf, BrowserMatch and
// SetEnv define for one request. A variable is unknown when a directive that
// would define it could not be evaluated (a PCRE-only regex, an attribute
// that is not available, a section whose condition cannot be decided); an
// "env=" condition on it then fails closed.
type envState struct {
	set     map[string]bool
	unknown map[string]bool
}

// attr returns the value of a SetEnvIf attribute. present is false when the
// request has no such attribute; known is false when it cannot be provided.
func (a *RequestAttrs) attr(name string) (val string, present, known bool) {
	switch strings.ToLower(name) {
	case "remote_addr", "remote_host":
		return a.RemoteAddr, a.RemoteAddr != "", true
	case "request_method":
		return a.Method, a.Method != "", true
	case "request_uri":
		return a.URI, a.URI != "", true
	case "request_protocol":
		return a.Proto, a.Proto != "", true
	case "remote_user":
		return "", false, true // authentication has not happened yet
	case "host":
		return a.Host, a.Host != "", true
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", false, false // a regex attribute, "Server_Addr", ...
		}
	}
	if name == "" || strings.EqualFold(name, "server_addr") {
		return "", false, false
	}
	if vals := a.Header.Values(name); len(vals) > 0 {
		return vals[0], true, true
	}
	return "", false, true
}

// buildEnv evaluates the SetEnv/SetEnvIf/BrowserMatch family among ds, in
// order, for a request. It returns nil when attrs is nil.
func buildEnv(ds []Directive, attrs *RequestAttrs) *envState {
	if attrs == nil {
		return nil
	}
	st := &envState{set: map[string]bool{}, unknown: map[string]bool{}}
	st.walk(ds, attrs, false)
	return st
}

// extendEnv applies further directives (a <Files> block's) to a copy of st.
func extendEnv(st *envState, ds []Directive, attrs *RequestAttrs) *envState {
	if st == nil || attrs == nil {
		return st
	}
	cp := &envState{set: map[string]bool{}, unknown: map[string]bool{}}
	for k, v := range st.set {
		cp.set[k] = v
	}
	for k, v := range st.unknown {
		cp.unknown[k] = v
	}
	cp.walk(ds, attrs, false)
	return cp
}

func (st *envState) walk(ds []Directive, a *RequestAttrs, opaque bool) {
	for _, d := range ds {
		args := d.Args
		switch strings.ToLower(d.Name) {
		case "setenv":
			if len(args) >= 1 {
				st.assign([]string{args[0]}, true, opaque)
			}
		case "unsetenv":
			for _, name := range args {
				st.assign([]string{"!" + name}, true, opaque)
			}
		case "setenvif", "setenvifnocase":
			if len(args) >= 3 {
				st.matchAndAssign(strings.EqualFold(d.Name, "setenvifnocase"), args[0], args[1], args[2:], a, opaque)
			}
		case "browsermatch", "browsermatchnocase":
			if len(args) >= 2 {
				st.matchAndAssign(strings.EqualFold(d.Name, "browsermatchnocase"), "User-Agent", args[0], args[1:], a, opaque)
			}
		default:
			if !isConditional(d.Name) {
				continue
			}
			switch conditionState(d) {
			case condActive:
				st.walk(d.Block, a, opaque)
			case condUnknown:
				st.walk(d.Block, a, true)
			}
		}
	}
}

func (st *envState) matchAndAssign(nocase bool, attr, pattern string, vars []string, a *RequestAttrs, opaque bool) {
	val, present, known := a.attr(attr)
	if !known || len(pattern) > MaxPatternLength {
		st.assign(vars, false, true)
		return
	}
	if nocase {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		st.assign(vars, false, true) // PCRE-only syntax: cannot decide
		return
	}
	if !present || !re.MatchString(val) {
		if opaque {
			st.assign(vars, false, true)
		}
		return
	}
	st.assign(vars, true, opaque)
}

// assign applies "name", "!name" or "name=value" entries. unknown marks them
// undecidable instead of applying them.
func (st *envState) assign(vars []string, apply, unknown bool) {
	for _, v := range vars {
		neg := strings.HasPrefix(v, "!")
		name, _, _ := strings.Cut(strings.TrimPrefix(v, "!"), "=")
		name = strings.ToLower(name)
		if name == "" {
			continue
		}
		if unknown {
			st.unknown[name] = true
			continue
		}
		if !apply {
			continue
		}
		delete(st.unknown, name)
		if neg {
			delete(st.set, name)
		} else {
			st.set[name] = true
		}
	}
}

// has reports whether name is defined; ok is false when that cannot be
// decided (no request attributes, or an unevaluable directive named it).
func (st *envState) has(name string) (set, ok bool) {
	if st == nil || st.unknown[name] {
		return false, false
	}
	return st.set[name], true
}
