package report

import "github.com/FlinnZee/breachhound/internal/core"

// GroupByTactic buckets findings by their MITRE ATT&CK tactic for reporting.
// Findings with no tactic are grouped under "Uncategorized".
func GroupByTactic(findings []core.Finding) map[string][]core.Finding {
	groups := map[string][]core.Finding{}
	for _, f := range findings {
		tactic := f.Tactic
		if tactic == "" {
			tactic = "Uncategorized"
		}
		groups[tactic] = append(groups[tactic], f)
	}
	return groups
}
