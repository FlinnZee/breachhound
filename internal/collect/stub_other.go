//go:build !windows

package collect

import "github.com/FlinnZee/breachhound/internal/core"

// BreachHound's collectors target Windows hosts. On other platforms (e.g. a
// Kali/Linux dev box used for cross-compiling) the collectors register but
// report themselves as skipped so the pipeline still runs end-to-end.

func init() {
	core.RegisterCollector(stubCollector("persistence"))
	core.RegisterCollector(stubCollector("processes"))
	core.RegisterCollector(stubCollector("network"))
	core.RegisterCollector(stubCollector("accounts"))
}

type stubCollector string

func (s stubCollector) Name() string { return string(s) }

func (s stubCollector) Collect(ctx *core.Context) error {
	ctx.Skip(string(s) + ": only supported on Windows hosts")
	return nil
}
