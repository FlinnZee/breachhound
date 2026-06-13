package core

import "fmt"

// Severity is the impact level of a finding.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// weight is the base score contribution of a severity level.
func (s Severity) weight() float64 {
	switch s {
	case SevInfo:
		return 0
	case SevLow:
		return 5
	case SevMedium:
		return 15
	case SevHigh:
		return 35
	case SevCritical:
		return 60
	default:
		return 0
	}
}

// Confidence reflects how sure the detector is that a finding is a true positive.
type Confidence int

const (
	ConfLow Confidence = iota
	ConfMedium
	ConfHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfLow:
		return "LOW"
	case ConfMedium:
		return "MEDIUM"
	case ConfHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// multiplier scales a finding's severity weight by detector confidence.
func (c Confidence) multiplier() float64 {
	switch c {
	case ConfLow:
		return 0.4
	case ConfMedium:
		return 0.7
	case ConfHigh:
		return 1.0
	default:
		return 0.4
	}
}

// Finding is a single detection result with the evidence behind it.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Technique   string   `json:"technique,omitempty"` // MITRE ATT&CK technique ID, e.g. T1547.001
	Tactic      string   `json:"tactic,omitempty"`    // MITRE ATT&CK tactic, e.g. Persistence
	Source      string   `json:"source"`              // detector that produced it
	Evidence    []string `json:"evidence,omitempty"`
}

// score is this finding's contribution to the host risk score.
func (f Finding) score() float64 {
	return f.Severity.weight() * f.Confidence.multiplier()
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s (%s, conf=%s, %s)", f.Severity, f.Title, f.Technique, f.Confidence, f.Source)
}
