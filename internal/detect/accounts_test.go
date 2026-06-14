package detect

import (
	"testing"

	"github.com/FlinnZee/breachhound/internal/core"
)

func TestAccountsFlagsEnabledGuest(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Users = []core.LocalUser{
		{Name: "Guest", Enabled: true, SID: "S-1-5-21-501"},
		{Name: "Alice", Enabled: true, SID: "S-1-5-21-1001"},
	}
	fs, err := accounts{}.Detect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].ID != "acct-guest-enabled" || fs[0].Severity != core.SevMedium {
		t.Errorf("unexpected finding: %+v", fs[0])
	}
}

func TestAccountsIgnoresDisabledGuest(t *testing.T) {
	ctx := core.NewContext(core.Config{})
	ctx.Host.Users = []core.LocalUser{
		{Name: "Guest", Enabled: false},
		{Name: "Administrator", Enabled: false},
	}
	fs, _ := accounts{}.Detect(ctx)
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}
