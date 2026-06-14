package detect

import (
	"fmt"
	"strings"

	"github.com/FlinnZee/breachhound/internal/core"
)

func init() { core.RegisterDetector(&accounts{}) }

// accounts flags notable local-account states. It stays conservative to avoid
// false positives on normal machines: an enabled Guest account, or an enabled
// built-in Administrator, are the high-signal cases.
type accounts struct{}

func (accounts) Name() string { return "accounts" }

func (a accounts) Detect(ctx *core.Context) ([]core.Finding, error) {
	var out []core.Finding
	for _, u := range ctx.Host.Users {
		if !u.Enabled {
			continue
		}
		name := strings.ToLower(u.Name)

		switch {
		case name == "guest":
			out = append(out, core.Finding{
				ID:          "acct-guest-enabled",
				Title:       "Guest account is enabled",
				Description: "The built-in Guest account is enabled. It is disabled by default and is a common foothold for unauthenticated access.",
				Severity:    core.SevMedium,
				Confidence:  core.ConfHigh,
				Technique:   "T1078.001",
				Tactic:      "Persistence",
				Source:      a.Name(),
				Evidence:    []string{fmt.Sprintf("%s (SID %s)", u.Name, u.SID)},
			})
		case name == "administrator":
			out = append(out, core.Finding{
				ID:          "acct-admin-enabled",
				Title:       "Built-in Administrator account is enabled",
				Description: "The built-in Administrator account is enabled. It is disabled by default on modern Windows; an enabled state is worth confirming.",
				Severity:    core.SevLow,
				Confidence:  core.ConfMedium,
				Technique:   "T1078.001",
				Tactic:      "Persistence",
				Source:      a.Name(),
				Evidence:    []string{fmt.Sprintf("%s (SID %s)", u.Name, u.SID)},
			})
		}
	}
	return out, nil
}
