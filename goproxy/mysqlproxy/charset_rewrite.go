package mysqlproxy

import "strings"

// safeResultsCharset is what a client's `character_set_results = NULL` is pinned to. utf8mb4 is full
// Unicode (unlike utf8/utf8mb3), so converting any column's text to it is lossless, and it satisfies the
// session charset invariant so the masker's UTF-8 decoding of result bytes stays sound.
const safeResultsCharset = "utf8mb4"

// neutralizeResultsCharsetNULL rewrites a statement that sets character_set_results to NULL — the session
// init MySQL Connector/J (and so DBeaver) sends by default — into one that sets it to utf8mb4, and reports
// whether it rewrote.
//
// `SET character_set_results = NULL` asks the server to return each column in its OWN charset, unconverted,
// so the client can decode client-side. The proxy masks result rows by decoding their bytes as UTF-8
// (engine.applyMaskKind), so a non-UTF-8 column under NULL would corrupt the mask — which is why the
// session invariant (checkSysVarInvariants / the pre-statement probe) refuses a non-utf8 results charset
// and closes the connection. Pinning results to utf8mb4 keeps them UTF-8 (masking-safe); the client, whose
// only reason to ask for NULL was to decode itself, still receives consistent utf8mb4 bytes and metadata
// and decodes correctly.
//
// Only the exact single-assignment session-scoped "character_set_results = NULL" is rewritten. Anything
// else — a multi-assignment SET, GLOBAL scope, an explicit non-utf8 charset, SET NAMES latin1 — is returned
// untouched and still fails closed at the existing guard, so a miss can never open a masking hole.
func neutralizeResultsCharsetNULL(sql string) (string, bool) {
	s := strings.TrimSpace(sql)
	s = strings.TrimSpace(strings.TrimSuffix(s, ";"))

	rest, ok := cutKeyword(s, "set")
	if !ok {
		return sql, false
	}
	rest = strings.TrimSpace(rest)
	// An optional session-scope keyword. GLOBAL is a different variable (the default for future
	// connections), not this session's, so it is left alone.
	scopeKeyword := false
	if after, ok := cutKeyword(rest, "session"); ok {
		rest, scopeKeyword = strings.TrimSpace(after), true
	} else if after, ok := cutKeyword(rest, "local"); ok {
		rest, scopeKeyword = strings.TrimSpace(after), true
	}

	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		return sql, false
	}
	// A comma before the '=' means more than one assignment; do not touch a compound SET.
	if strings.IndexByte(rest[:eq], ',') >= 0 {
		return sql, false
	}
	// A scope keyword together with an @@ sigil (SET SESSION @@x) is invalid MySQL; leave it for the
	// backend to reject rather than normalizing it into a statement it would refuse.
	if scopeKeyword && strings.HasPrefix(strings.TrimSpace(rest[:eq]), "@@") {
		return sql, false
	}
	lhs := normalizeSysVarName(rest[:eq])
	rhs := strings.TrimSpace(rest[eq+1:])
	// A comma after the value is a second assignment too.
	if strings.IndexByte(rhs, ',') >= 0 {
		return sql, false
	}
	if lhs != "character_set_results" || !strings.EqualFold(rhs, "null") {
		return sql, false
	}
	return "SET character_set_results = " + safeResultsCharset, true
}

// normalizeSysVarName strips the @@ / @@session. / @@local. sigils MySQL accepts on a system-variable name
// and lowercases it, so a name written any of those ways compares equal to its bare form. A scope qualifier
// is stripped ONLY after @@, and AT MOST ONE of them: a bare `session.`/`local.` prefix and a doubled
// `@@session.local.` are both invalid MySQL, so neither must normalize to the bare name and match. @@global.
// keeps its prefix, so a global var never matches a session one.
func normalizeSysVarName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	rest, ok := strings.CutPrefix(n, "@@")
	if !ok {
		return n
	}
	if after, ok := strings.CutPrefix(rest, "session."); ok {
		return after
	}
	if after, ok := strings.CutPrefix(rest, "local."); ok {
		return after
	}
	return rest
}

// cutKeyword returns the remainder of s after a leading keyword (case-insensitive) that is followed by
// whitespace or an '@' — so it matches the keyword as a whole word, never a prefix of a longer identifier.
func cutKeyword(s, kw string) (string, bool) {
	if len(s) <= len(kw) || !strings.EqualFold(s[:len(kw)], kw) {
		return "", false
	}
	switch s[len(kw)] {
	case ' ', '\t', '\n', '\r', '@':
		return s[len(kw):], true
	}
	return "", false
}
