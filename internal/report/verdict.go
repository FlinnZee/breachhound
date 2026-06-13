package report

import (
	"fmt"
	"io"

	"github.com/FlinnZee/breachhound/internal/core"
)

// PrintVerdict writes the plain-English bottom line to w: the verdict, the
// risk score, and the top reasons in language anyone can read.
func PrintVerdict(w io.Writer, host *core.HostModel, r core.Result) {
	fmt.Fprintln(w, "============================================================")
	fmt.Fprintf(w, "  %s v%s — by %s\n", core.Name, core.Version, core.Author)
	fmt.Fprintf(w, "  Compromise Assessment for %s\n", host.Hostname)
	fmt.Fprintln(w, "============================================================")
	fmt.Fprintf(w, "  VERDICT:  %s   (risk score %d/100)\n", r.Verdict, r.RiskScore)
	fmt.Fprintln(w, "------------------------------------------------------------")

	switch r.Verdict {
	case core.VerdictClean:
		fmt.Fprintln(w, "  No strong signs of compromise were found in what we could")
		fmt.Fprintln(w, "  examine. This is reassuring but not a guarantee.")
	case core.VerdictReview:
		fmt.Fprintln(w, "  Some things look unusual and deserve a closer look by a")
		fmt.Fprintln(w, "  person. They are not proof of a hack on their own.")
	case core.VerdictCompromised:
		fmt.Fprintln(w, "  We found strong indicators that this machine may be")
		fmt.Fprintln(w, "  compromised. Treat it as suspect and investigate now.")
	}

	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "\n  Top reasons:")
		for i, f := range r.Findings {
			if i >= 5 {
				break
			}
			fmt.Fprintf(w, "    - [%s] %s\n", f.Severity, f.Title)
		}
	}

	if len(r.Skipped) > 0 {
		fmt.Fprintf(w, "\n  Note: %d check(s) were skipped (often needs Administrator):\n", len(r.Skipped))
		for _, s := range r.Skipped {
			fmt.Fprintf(w, "    - %s\n", s)
		}
	}
	fmt.Fprintln(w, "============================================================")
}
