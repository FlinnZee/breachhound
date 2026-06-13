// Command breachhound runs a read-only compromise assessment on the local
// host and reports a plain-English verdict plus machine-readable evidence.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/FlinnZee/breachhound/internal/collect"
	"github.com/FlinnZee/breachhound/internal/core"
	"github.com/FlinnZee/breachhound/internal/report"
)

func main() {
	var (
		quick   = flag.Bool("quick", false, "run a faster, lighter scan")
		outDir  = flag.String("out", ".", "directory for report.json / report.html")
		formats = flag.String("format", "json,html", "comma-separated report formats: json,html")
	)
	flag.Parse()

	cfg := core.Config{
		Quick:      *quick,
		OutDir:     *outDir,
		Formats:    splitCSV(*formats),
		WarnOnSkip: true,
	}

	ctx := core.NewContext(cfg)
	host, _ := os.Hostname()
	ctx.Host.Hostname = host
	ctx.Host.OS = runtime.GOOS
	ctx.Host.Elevated = collect.IsElevated()
	ctx.Host.CollectedAt = time.Now()

	if !ctx.Host.Elevated {
		ctx.Logger.Println("not elevated: some checks will be skipped (run as Administrator for full coverage)")
	}

	ctx.Run()
	result := core.Score(ctx.Findings(), ctx.Skipped())

	report.PrintVerdict(os.Stdout, ctx.Host, result)

	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		ctx.Logger.Printf("cannot create output dir: %v", err)
		os.Exit(1)
	}
	for _, f := range cfg.Formats {
		switch f {
		case "json":
			if path, err := report.WriteJSON(cfg.OutDir, ctx.Host, result); err != nil {
				ctx.Logger.Printf("json report failed: %v", err)
			} else {
				fmt.Printf("wrote %s\n", path)
			}
		case "html":
			if path, err := report.WriteHTML(cfg.OutDir, ctx.Host, result); err != nil {
				ctx.Logger.Printf("html report failed: %v", err)
			} else {
				fmt.Printf("wrote %s\n", path)
			}
		}
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
