package core

import "testing"

func TestVerdictThresholds(t *testing.T) {
	cases := []struct {
		risk int
		want Verdict
	}{
		{0, VerdictClean},
		{19, VerdictClean},
		{20, VerdictReview},
		{59, VerdictReview},
		{60, VerdictCompromised},
		{100, VerdictCompromised},
	}
	for _, c := range cases {
		if got := verdictFor(c.risk); got != c.want {
			t.Errorf("verdictFor(%d) = %q, want %q", c.risk, got, c.want)
		}
	}
}

func TestScoreCapsAt100(t *testing.T) {
	var fs []Finding
	for i := 0; i < 10; i++ {
		fs = append(fs, Finding{Severity: SevCritical, Confidence: ConfHigh})
	}
	r := Score(fs, nil)
	if r.RiskScore != 100 {
		t.Errorf("RiskScore = %d, want capped at 100", r.RiskScore)
	}
	if r.Verdict != VerdictCompromised {
		t.Errorf("Verdict = %q, want %q", r.Verdict, VerdictCompromised)
	}
}

func TestScoreSortsBySeverityThenConfidence(t *testing.T) {
	fs := []Finding{
		{Title: "low", Severity: SevLow, Confidence: ConfHigh},
		{Title: "crit", Severity: SevCritical, Confidence: ConfLow},
		{Title: "high-hi", Severity: SevHigh, Confidence: ConfHigh},
		{Title: "high-lo", Severity: SevHigh, Confidence: ConfLow},
	}
	r := Score(fs, nil)
	want := []string{"crit", "high-hi", "high-lo", "low"}
	for i, w := range want {
		if r.Findings[i].Title != w {
			t.Errorf("Findings[%d] = %q, want %q", i, r.Findings[i].Title, w)
		}
	}
}

func TestEmptyScanLooksClean(t *testing.T) {
	r := Score(nil, nil)
	if r.RiskScore != 0 || r.Verdict != VerdictClean {
		t.Errorf("empty scan = (%d, %q), want (0, %q)", r.RiskScore, r.Verdict, VerdictClean)
	}
}

func TestConfidenceScalesScore(t *testing.T) {
	hi := Score([]Finding{{Severity: SevHigh, Confidence: ConfHigh}}, nil).RiskScore
	lo := Score([]Finding{{Severity: SevHigh, Confidence: ConfLow}}, nil).RiskScore
	if !(hi > lo) {
		t.Errorf("high-confidence score (%d) should exceed low-confidence (%d)", hi, lo)
	}
}
