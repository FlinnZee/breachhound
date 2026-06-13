package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/FlinnZee/breachhound/internal/core"
)

// jsonReport is the machine-readable on-disk shape of a scan.
type jsonReport struct {
	Tool        string         `json:"tool"`
	Version     string         `json:"version"`
	Author      string         `json:"author"`
	GeneratedAt time.Time      `json:"generated_at"`
	Host        *core.HostModel `json:"host"`
	RiskScore   int            `json:"risk_score"`
	Verdict     core.Verdict   `json:"verdict"`
	Findings    []finding      `json:"findings"`
	Skipped     []string       `json:"skipped,omitempty"`
}

// finding mirrors core.Finding but renders severity/confidence as strings so
// the JSON is readable without the enum legend.
type finding struct {
	core.Finding
	SeverityText   string `json:"severity_text"`
	ConfidenceText string `json:"confidence_text"`
}

// WriteJSON writes report.json into dir and returns its path.
func WriteJSON(dir string, host *core.HostModel, r core.Result) (string, error) {
	rep := jsonReport{
		Tool:        core.Name,
		Version:     core.Version,
		Author:      core.Author,
		GeneratedAt: time.Now(),
		Host:        host,
		RiskScore:   r.RiskScore,
		Verdict:     r.Verdict,
		Skipped:     r.Skipped,
	}
	for _, f := range r.Findings {
		rep.Findings = append(rep.Findings, finding{
			Finding:        f,
			SeverityText:   f.Severity.String(),
			ConfidenceText: f.Confidence.String(),
		})
	}

	path := filepath.Join(dir, "report.json")
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
