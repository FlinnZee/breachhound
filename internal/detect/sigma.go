package detect

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/FlinnZee/breachhound/internal/core"
	"github.com/FlinnZee/breachhound/internal/rules"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
)

func init() { core.RegisterDetector(&sigmaDetector{}) }

// sigmaDetector evaluates embedded Sigma rules against collected event-log
// records and turns matches into findings.
type sigmaDetector struct{}

func (sigmaDetector) Name() string { return "sigma" }

type compiledRule struct {
	rule sigma.Rule
	eval *evaluator.RuleEvaluator
}

var (
	sigmaOnce  sync.Once
	sigmaRules []compiledRule
)

func loadSigma() {
	for _, raw := range rules.SigmaRules() {
		rule, err := sigma.ParseRule(raw)
		if err != nil {
			continue
		}
		sigmaRules = append(sigmaRules, compiledRule{rule: rule, eval: evaluator.ForRule(rule)})
	}
}

func (s sigmaDetector) Detect(ctx *core.Context) ([]core.Finding, error) {
	sigmaOnce.Do(loadSigma)
	if len(sigmaRules) == 0 || len(ctx.Host.Events) == 0 {
		return nil, nil
	}

	var out []core.Finding
	seen := map[string]bool{}
	for _, e := range ctx.Host.Events {
		ev := eventMap(e)
		for _, cr := range sigmaRules {
			res, err := cr.eval.Matches(context.Background(), ev)
			if err != nil || !res.Match {
				continue
			}
			tech, tactic := attackFromTags(cr.rule.Tags)
			id := fmt.Sprintf("sigma-%s-%d", cr.rule.ID, e.ID)
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, core.Finding{
				ID:          id,
				Title:       cr.rule.Title,
				Description: sigmaDescription(cr.rule),
				Severity:    severityForLevel(cr.rule.Level),
				Confidence:  core.ConfMedium,
				Technique:   tech,
				Tactic:      tactic,
				Source:      s.Name(),
				Evidence:    []string{fmt.Sprintf("%s event %d", e.Channel, e.ID), e.Message},
			})
		}
	}
	return out, nil
}

// eventMap projects an Event into the flat field map Sigma rules match against.
func eventMap(e core.Event) map[string]interface{} {
	m := map[string]interface{}{
		"EventID":       e.ID,
		"Channel":       e.Channel,
		"Provider_Name": e.Provider,
		"Message":       e.Message,
	}
	for k, v := range e.Data {
		m[k] = v
	}
	return m
}

func sigmaDescription(r sigma.Rule) string {
	if strings.TrimSpace(r.Description) != "" {
		return r.Description
	}
	return r.Title
}

func severityForLevel(level string) core.Severity {
	switch strings.ToLower(level) {
	case "critical":
		return core.SevCritical
	case "high":
		return core.SevHigh
	case "medium":
		return core.SevMedium
	case "low":
		return core.SevLow
	default:
		return core.SevInfo
	}
}

// attackFromTags extracts a MITRE technique ID and tactic from Sigma tags such
// as "attack.t1059.001" and "attack.execution".
func attackFromTags(tags []string) (technique, tactic string) {
	for _, t := range tags {
		tl := strings.ToLower(t)
		switch {
		case strings.HasPrefix(tl, "attack.t"):
			technique = strings.ToUpper(strings.TrimPrefix(tl, "attack."))
		case strings.HasPrefix(tl, "attack."):
			tactic = tacticName(strings.TrimPrefix(tl, "attack."))
		}
	}
	return technique, tactic
}

func tacticName(s string) string {
	s = strings.ReplaceAll(s, "_", " ")
	parts := strings.Fields(s)
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}
