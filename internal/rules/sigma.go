package rules

import "embed"

//go:embed sigma/*.yml
var sigmaFS embed.FS

// SigmaRules returns the raw bytes of every embedded Sigma rule.
func SigmaRules() [][]byte {
	var out [][]byte
	entries, err := sigmaFS.ReadDir("sigma")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if b, err := sigmaFS.ReadFile("sigma/" + e.Name()); err == nil {
			out = append(out, b)
		}
	}
	return out
}
