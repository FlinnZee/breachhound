package main

import (
	"os"
	"runtime"
	"time"

	"github.com/FlinnZee/breachhound/internal/collect"
	"github.com/FlinnZee/breachhound/internal/core"
)

// scanResult bundles everything the UI needs to render once a scan finishes.
type scanResult struct {
	Host     *core.HostModel
	Result   core.Result
	Duration time.Duration
}

// quickHostInfo returns lightweight host identity for the window header,
// without running the full scan pipeline.
func quickHostInfo() (name, osName string, elevated bool) {
	name, _ = os.Hostname()
	return name, runtime.GOOS, collect.IsElevated()
}

// stageCount is the number of collector + detector stages a full run executes.
// The UI uses it to drive a determinate progress bar.
func stageCount() int {
	return len(core.Collectors()) + len(core.Detectors())
}

// runScan executes the full read-only collect/detect/score pipeline. onStage is
// invoked as each stage begins; it runs on the scan goroutine, so the caller is
// responsible for marshaling any UI updates back to the main thread.
func runScan(quick bool, onStage func(phase, name string)) scanResult {
	ctx := core.NewContext(core.Config{Quick: quick, WarnOnSkip: true})

	host, _ := os.Hostname()
	ctx.Host.Hostname = host
	ctx.Host.OS = runtime.GOOS
	ctx.Host.Elevated = collect.IsElevated()
	ctx.Host.CollectedAt = time.Now()
	ctx.OnStage = onStage

	start := time.Now()
	ctx.Run()
	return scanResult{
		Host:     ctx.Host,
		Result:   core.Score(ctx.Findings(), ctx.Skipped()),
		Duration: time.Since(start),
	}
}
