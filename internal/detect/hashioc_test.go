package detect

import (
	"testing"

	"github.com/FlinnZee/breachhound/internal/core"
)

// eicarSHA256 is the SHA-256 of the EICAR test string, which ships in the
// embedded bad-hash feed.
const eicarSHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

func TestIOCMatchesBadHash(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Processes = []core.Process{
		{PID: 42, Name: "evil.exe", Path: `C:\Temp\evil.exe`, SHA256: eicarSHA256},
		{PID: 43, Name: "clean.exe", Path: `C:\Windows\clean.exe`, SHA256: "deadbeef"},
	}
	fs, err := ioc{}.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].ID != "ioc-hash-42" || fs[0].Severity != core.SevCritical {
		t.Errorf("unexpected finding: %+v", fs[0])
	}
}
