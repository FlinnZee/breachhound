package core

import (
	"log"
	"os"
	"sync"
)

// Config holds run-time options parsed from the CLI.
type Config struct {
	Quick      bool
	OutDir     string
	Formats    []string // json, html
	WarnOnSkip bool
}

// Context is threaded through the whole pipeline. It owns the host model,
// the accumulated findings, and the logger. It is safe for collectors and
// detectors to call AddFinding / Skip concurrently.
type Context struct {
	Config Config
	Host   *HostModel
	Logger *log.Logger

	// OnStage, if set, is invoked as each pipeline stage runs (phase is
	// "collect" or "detect", name is the collector/detector name). It lets a
	// front-end such as the GUI report live progress. It may be called from
	// the pipeline goroutine, so implementations must be safe to call there.
	OnStage func(phase, name string)

	mu       sync.Mutex
	findings []Finding
	skipped  []string
}

// NewContext builds a Context with an empty host model ready for collection.
func NewContext(cfg Config) *Context {
	return &Context{
		Config: cfg,
		Host:   &HostModel{},
		Logger: log.New(os.Stderr, "", log.LstdFlags),
	}
}

// stage reports pipeline progress to the OnStage hook if one is set.
func (c *Context) stage(phase, name string) {
	if c.OnStage != nil {
		c.OnStage(phase, name)
	}
}

// AddFinding records a detection result.
func (c *Context) AddFinding(f Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.findings = append(c.findings, f)
}

// Findings returns a copy-safe view of all findings gathered so far.
func (c *Context) Findings() []Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Finding, len(c.findings))
	copy(out, c.findings)
	return out
}

// Skip records that a collector could not run (e.g. missing privileges) so
// the report can clearly state what was not examined.
func (c *Context) Skip(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.skipped = append(c.skipped, reason)
	c.Logger.Printf("skipped: %s", reason)
}

// Skipped returns the list of skip reasons recorded during the run.
func (c *Context) Skipped() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.skipped))
	copy(out, c.skipped)
	return out
}
