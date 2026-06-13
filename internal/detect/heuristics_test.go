package detect

import (
	"testing"

	"github.com/FlinnZee/breachhound/internal/core"
)

func findByID(fs []core.Finding, id string) (core.Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return core.Finding{}, false
}

func TestHeuristicsUnsignedInTemp(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Processes = []core.Process{
		{PID: 100, Name: "evil.exe", Path: `C:\Users\bob\AppData\Local\Temp\evil.exe`, Signed: false},
		{PID: 101, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`, Signed: true},
	}
	fs, err := heuristics{}.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "heur-unsigned-temp-100"); !ok {
		t.Error("expected unsigned-in-temp finding for PID 100")
	}
	if _, ok := findByID(fs, "heur-unsigned-temp-101"); ok {
		t.Error("signed system binary should not be flagged")
	}
}

func TestHeuristicsDocumentSpawnsShell(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Processes = []core.Process{
		{PID: 200, Name: "WINWORD.EXE", Path: `C:\Program Files\Office\WINWORD.EXE`, Signed: true},
		{PID: 201, PPID: 200, Name: "powershell.exe", CmdLine: "powershell -nop -w hidden"},
	}
	fs, err := heuristics{}.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "heur-spawn-201")
	if !ok {
		t.Fatal("expected document-spawns-shell finding")
	}
	if f.Technique != "T1566.001" {
		t.Errorf("technique = %q, want T1566.001", f.Technique)
	}
}

func TestHeuristicsEncodedPowerShell(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Processes = []core.Process{
		{PID: 300, Name: "powershell.exe", CmdLine: "powershell.exe -EncodedCommand ZQBjAGgAbwA="},
	}
	fs, _ := heuristics{}.Detect(ctx)
	if _, ok := findByID(fs, "heur-ps-enc-300"); !ok {
		t.Error("expected encoded-powershell finding")
	}
}

func TestHeuristicsCleanHostNoFindings(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Processes = []core.Process{
		{PID: 1, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`, Signed: true},
	}
	fs, _ := heuristics{}.Detect(ctx)
	if len(fs) != 0 {
		t.Errorf("clean host produced %d findings, want 0: %v", len(fs), fs)
	}
}
