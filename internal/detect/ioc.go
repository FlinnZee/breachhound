package detect

import (
	"fmt"
	"strings"

	"github.com/FlinnZee/breachhound/internal/core"
	"github.com/FlinnZee/breachhound/internal/rules"
)

func init() { core.RegisterDetector(&ioc{}) }

// ioc matches collected artifacts against known-bad indicator feeds.
type ioc struct{}

func (ioc) Name() string { return "ioc" }

func (i ioc) Detect(ctx *core.Context) ([]core.Finding, error) {
	var out []core.Finding

	badIPs := rules.BadIPSet()
	badDomains := rules.BadDomainSet()
	badHashes := rules.BadHashSet()

	// Process images whose SHA-256 matches a known-bad hash.
	for _, p := range ctx.Host.Processes {
		if p.SHA256 == "" {
			continue
		}
		if _, bad := badHashes[strings.ToLower(p.SHA256)]; bad {
			out = append(out, core.Finding{
				ID:          fmt.Sprintf("ioc-hash-%d", p.PID),
				Title:       "Process image matches a known-bad hash",
				Description: fmt.Sprintf("The image for %q (PID %d) matches a known-bad SHA-256 indicator.", p.Name, p.PID),
				Severity:    core.SevCritical,
				Confidence:  core.ConfHigh,
				Technique:   "T1204",
				Tactic:      "Execution",
				Source:      i.Name(),
				Evidence:    []string{p.Path, p.SHA256},
			})
		}
	}

	// Network connections to known-bad remote IPs.
	for _, c := range ctx.Host.Connections {
		if c.RemoteAddr == "" {
			continue
		}
		if _, bad := badIPs[c.RemoteAddr]; bad {
			out = append(out, core.Finding{
				ID:         fmt.Sprintf("ioc-ip-%s-%d", c.RemoteAddr, c.PID),
				Title:      "Connection to known-bad IP",
				Description: fmt.Sprintf("Process %q connected to known-bad IP %s:%d.", c.ProcessName, c.RemoteAddr, c.RemotePort),
				Severity:   core.SevCritical,
				Confidence: core.ConfHigh,
				Technique:  "T1071",
				Tactic:     "Command and Control",
				Source:     i.Name(),
				Evidence:   []string{fmt.Sprintf("%s -> %s:%d (%s)", c.ProcessName, c.RemoteAddr, c.RemotePort, c.Proto)},
			})
		}
	}

	// Process command lines referencing known-bad domains.
	for _, p := range ctx.Host.Processes {
		lcmd := strings.ToLower(p.CmdLine)
		for d := range badDomains {
			if strings.Contains(lcmd, d) {
				out = append(out, core.Finding{
					ID:         fmt.Sprintf("ioc-domain-%d", p.PID),
					Title:      "Process references known-bad domain",
					Description: fmt.Sprintf("Process %q references known-bad domain %q on its command line.", p.Name, d),
					Severity:   core.SevHigh,
					Confidence: core.ConfHigh,
					Technique:  "T1071.001",
					Tactic:     "Command and Control",
					Source:     i.Name(),
					Evidence:   []string{p.CmdLine},
				})
			}
		}
	}

	return out, nil
}
