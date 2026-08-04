package mysqlproxy

import "testing"

func TestNeutralizeResultsCharsetNULL(t *testing.T) {
	const want = "SET character_set_results = utf8mb4"
	tests := []struct {
		name       string
		sql        string
		wantSQL    string
		wantRewrit bool
	}{
		// Rewritten: the Connector/J default and its accepted spellings.
		{"connectorj default", "SET character_set_results = NULL", want, true},
		{"no spaces", "SET character_set_results=NULL", want, true},
		{"lowercase null", "set character_set_results = null", want, true},
		{"trailing semicolon", "SET character_set_results = NULL;", want, true},
		{"trailing whitespace", "  SET character_set_results = NULL  ", want, true},
		{"session keyword", "SET SESSION character_set_results = NULL", want, true},
		{"local keyword", "SET LOCAL character_set_results = NULL", want, true},
		{"at-at sigil", "SET @@character_set_results = NULL", want, true},
		{"at-at session", "SET @@session.character_set_results = NULL", want, true},
		{"at-at local", "SET @@local.character_set_results = null", want, true},

		// Left untouched (and thus still fail closed at the existing guard).
		{"already utf8mb4", "SET character_set_results = utf8mb4", "SET character_set_results = utf8mb4", false},
		{"explicit latin1", "SET character_set_results = latin1", "SET character_set_results = latin1", false},
		{"global scope", "SET GLOBAL character_set_results = NULL", "SET GLOBAL character_set_results = NULL", false},
		{"at-at global", "SET @@global.character_set_results = NULL", "SET @@global.character_set_results = NULL", false},
		{"set names latin1", "SET NAMES latin1", "SET NAMES latin1", false},
		{"multi assignment before", "SET autocommit = 1, character_set_results = NULL", "SET autocommit = 1, character_set_results = NULL", false},
		{"multi assignment after", "SET character_set_results = NULL, autocommit = 1", "SET character_set_results = NULL, autocommit = 1", false},
		{"different var to null", "SET character_set_client = NULL", "SET character_set_client = NULL", false},
		{"value is not null keyword", "SET character_set_results = 'NULL'", "SET character_set_results = 'NULL'", false},
		{"not a set", "SELECT character_set_results", "SELECT character_set_results", false},
		{"var is a prefix (settle)", "SET settle = NULL", "SET settle = NULL", false},
		{"results var is a prefix", "SET character_set_results_x = NULL", "SET character_set_results_x = NULL", false},
		// A bare session./local. prefix (no @@) is not a valid sysvar name, so it must not normalize to the
		// bare form; and a scope keyword together with an @@ sigil is invalid MySQL — leave both for the backend.
		{"bare session-dot prefix", "SET SESSION.character_set_results = NULL", "SET SESSION.character_set_results = NULL", false},
		{"scope keyword with at-at", "SET SESSION @@session.character_set_results = NULL", "SET SESSION @@session.character_set_results = NULL", false},
		// A doubled @@session.local. qualifier and a doubled statement terminator are both invalid MySQL, so
		// they must not normalize/strip down to a matching form and be turned into a successful SET.
		{"doubled scope qualifier", "SET @@session.local.character_set_results = NULL", "SET @@session.local.character_set_results = NULL", false},
		{"doubled semicolon", "SET character_set_results = NULL;;", "SET character_set_results = NULL;;", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, rewrit := neutralizeResultsCharsetNULL(tc.sql)
			if rewrit != tc.wantRewrit {
				t.Fatalf("rewrote = %v, want %v (sql=%q)", rewrit, tc.wantRewrit, tc.sql)
			}
			if got != tc.wantSQL {
				t.Fatalf("sql = %q, want %q", got, tc.wantSQL)
			}
		})
	}
}
