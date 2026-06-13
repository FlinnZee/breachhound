package rules

import (
	_ "embed"
	"bufio"
	"strings"
)

// Indicator feeds are embedded so the single binary ships self-contained.
// One indicator per line; lines starting with '#' and blanks are ignored.

//go:embed feeds/bad_ips.txt
var badIPs string

//go:embed feeds/bad_domains.txt
var badDomains string

// BadIPSet returns the embedded known-bad IP indicators as a set.
func BadIPSet() map[string]struct{} { return toSet(badIPs, false) }

// BadDomainSet returns the embedded known-bad domain indicators as a set
// (lower-cased for case-insensitive matching).
func BadDomainSet() map[string]struct{} { return toSet(badDomains, true) }

func toSet(blob string, lower bool) map[string]struct{} {
	set := map[string]struct{}{}
	sc := bufio.NewScanner(strings.NewReader(blob))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if lower {
			line = strings.ToLower(line)
		}
		set[line] = struct{}{}
	}
	return set
}
