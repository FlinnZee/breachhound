package detect

import (
	"fmt"
	"strings"

	"github.com/FlinnZee/breachhound/internal/core"
)

func init() { core.RegisterDetector(&heuristics{}) }

// heuristics flags suspicious behavioral patterns in the collected host model.
type heuristics struct{}

func (heuristics) Name() string { return "heuristics" }

// userWritablePathHints are path fragments that suggest a binary lives in a
// location a low-privileged user (or attacker) can write to.
var userWritablePathHints = []string{
	`\temp\`, `\tmp\`, `\appdata\`, `\downloads\`,
	`\users\public\`, `\programdata\`, `\windows\temp\`,
}

// lolbins are living-off-the-land binaries frequently abused for download/exec.
var lolbins = []string{
	"rundll32", "mshta", "certutil", "regsvr32", "bitsadmin", "wmic",
	"msbuild", "installutil", "regasm", "regsvcs", "cmstp", "wscript", "cscript",
}

// downloadFlags are argument fragments that indicate remote content fetch/exec.
var downloadFlags = []string{"http://", "https://", "/urlcache", "-urlcache", "downloadstring", "iwr ", "invoke-webrequest"}

// suspiciousParents are office/document hosts that should rarely spawn shells.
var suspiciousParents = []string{"winword", "excel", "powerpnt", "outlook", "acrobat", "acrord32"}

// shellChildren are interpreters that are suspicious as children of documents.
var shellChildren = []string{"powershell", "pwsh", "cmd", "wscript", "cscript", "mshta"}

func (h heuristics) Detect(ctx *core.Context) ([]core.Finding, error) {
	var out []core.Finding
	byPID := map[int]core.Process{}
	for _, p := range ctx.Host.Processes {
		byPID[p.PID] = p
	}

	for _, p := range ctx.Host.Processes {
		lpath := strings.ToLower(p.Path)
		lcmd := strings.ToLower(p.CmdLine)
		lname := strings.ToLower(p.Name)

		// Unsigned binary running from a user-writable location.
		if !p.Signed && inUserWritable(lpath) {
			out = append(out, core.Finding{
				ID:         fmt.Sprintf("heur-unsigned-temp-%d", p.PID),
				Title:      "Unsigned binary executing from user-writable path",
				Description: fmt.Sprintf("Process %q (PID %d) is unsigned and runs from %q.", p.Name, p.PID, p.Path),
				Severity:   core.SevHigh,
				Confidence: core.ConfMedium,
				Technique:  "T1036",
				Tactic:     "Defense Evasion",
				Source:     h.Name(),
				Evidence:   []string{p.Path, p.CmdLine},
			})
		}

		// Any process executing from the Recycle Bin is highly suspicious.
		if strings.Contains(lpath, `\$recycle.bin\`) {
			out = append(out, core.Finding{
				ID:          fmt.Sprintf("heur-recyclebin-%d", p.PID),
				Title:       "Process running from the Recycle Bin",
				Description: fmt.Sprintf("Process %q (PID %d) is executing from the Recycle Bin, a classic hiding spot for malware.", p.Name, p.PID),
				Severity:    core.SevHigh,
				Confidence:  core.ConfHigh,
				Technique:   "T1036",
				Tactic:      "Defense Evasion",
				Source:      h.Name(),
				Evidence:    []string{p.Path, p.CmdLine},
			})
		}

		// LOLBin invoked with download/exec style arguments.
		if isLOLBin(lname) && hasDownloadFlag(lcmd) {
			out = append(out, core.Finding{
				ID:         fmt.Sprintf("heur-lolbin-%d", p.PID),
				Title:      "LOLBin invoked with remote download arguments",
				Description: fmt.Sprintf("%q was launched with arguments that fetch remote content.", p.Name),
				Severity:   core.SevHigh,
				Confidence: core.ConfMedium,
				Technique:  "T1218",
				Tactic:     "Defense Evasion",
				Source:     h.Name(),
				Evidence:   []string{p.CmdLine},
			})
		}

		// Encoded PowerShell command line.
		if strings.Contains(lname, "powershell") || strings.Contains(lname, "pwsh") {
			if strings.Contains(lcmd, "-enc") || strings.Contains(lcmd, "-e ") || strings.Contains(lcmd, "encodedcommand") {
				out = append(out, core.Finding{
					ID:         fmt.Sprintf("heur-ps-enc-%d", p.PID),
					Title:      "Encoded PowerShell command line",
					Description: "PowerShell was launched with an encoded command, a common obfuscation technique.",
					Severity:   core.SevMedium,
					Confidence: core.ConfMedium,
					Technique:  "T1059.001",
					Tactic:     "Execution",
					Source:     h.Name(),
					Evidence:   []string{p.CmdLine},
				})
			}
		}

		// Document host spawning a shell interpreter.
		if parent, ok := byPID[p.PPID]; ok {
			pname := strings.ToLower(parent.Name)
			if isDocumentHost(pname) && isShellChild(lname) {
				out = append(out, core.Finding{
					ID:         fmt.Sprintf("heur-spawn-%d", p.PID),
					Title:      "Document application spawned a shell",
					Description: fmt.Sprintf("%q spawned %q — a classic malicious-macro / exploit pattern.", parent.Name, p.Name),
					Severity:   core.SevHigh,
					Confidence: core.ConfHigh,
					Technique:  "T1566.001",
					Tactic:     "Initial Access",
					Source:     h.Name(),
					Evidence:   []string{fmt.Sprintf("%s (PID %d) -> %s (PID %d)", parent.Name, parent.PID, p.Name, p.PID), p.CmdLine},
				})
			}
		}
	}

	// Services / persistence pointing at user-writable paths.
	for _, item := range ctx.Host.Persistence {
		if inUserWritable(strings.ToLower(item.Command)) {
			out = append(out, core.Finding{
				ID:         "heur-persist-" + strings.ToLower(item.Type) + "-" + item.Name,
				Title:      "Persistence entry points to a user-writable path",
				Description: fmt.Sprintf("%s %q executes %q from a user-writable location.", item.Type, item.Name, item.Command),
				Severity:   core.SevHigh,
				Confidence: core.ConfMedium,
				Technique:  "T1543",
				Tactic:     "Persistence",
				Source:     h.Name(),
				Evidence:   []string{item.Location, item.Command},
			})
		}
	}

	return out, nil
}

func inUserWritable(lpath string) bool {
	for _, h := range userWritablePathHints {
		if strings.Contains(lpath, h) {
			return true
		}
	}
	return false
}

func isLOLBin(lname string) bool {
	for _, b := range lolbins {
		if strings.Contains(lname, b) {
			return true
		}
	}
	return false
}

func hasDownloadFlag(lcmd string) bool {
	for _, f := range downloadFlags {
		if strings.Contains(lcmd, f) {
			return true
		}
	}
	return false
}

func isDocumentHost(lname string) bool {
	for _, p := range suspiciousParents {
		if strings.Contains(lname, p) {
			return true
		}
	}
	return false
}

func isShellChild(lname string) bool {
	for _, c := range shellChildren {
		if strings.Contains(lname, c) {
			return true
		}
	}
	return false
}
