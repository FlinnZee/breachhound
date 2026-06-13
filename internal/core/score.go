package core

import "sort"

// Verdict is the plain-English bottom line for a scan.
type Verdict string

const (
	VerdictClean       Verdict = "LOOKS CLEAN"
	VerdictReview      Verdict = "NEEDS REVIEW"
	VerdictCompromised Verdict = "LIKELY COMPROMISED"
)

// Result is the scored outcome of a scan: a 0-100 risk score, the verdict it
// maps to, and the findings sorted most-severe first.
type Result struct {
	RiskScore int       `json:"risk_score"`
	Verdict   Verdict   `json:"verdict"`
	Findings  []Finding `json:"findings"`
	Skipped   []string  `json:"skipped,omitempty"`
}

// Score aggregates findings into a risk score and verdict. The score is the
// summed weighted contribution of every finding, capped at 100.
func Score(findings []Finding, skipped []string) Result {
	var total float64
	for _, f := range findings {
		total += f.score()
	}
	risk := int(total)
	if risk > 100 {
		risk = 100
	}

	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity > sorted[j].Severity
		}
		return sorted[i].Confidence > sorted[j].Confidence
	})

	return Result{
		RiskScore: risk,
		Verdict:   verdictFor(risk),
		Findings:  sorted,
		Skipped:   skipped,
	}
}

func verdictFor(risk int) Verdict {
	switch {
	case risk >= 60:
		return VerdictCompromised
	case risk >= 20:
		return VerdictReview
	default:
		return VerdictClean
	}
}
