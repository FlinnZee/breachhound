//go:build windows

package collect

import (
	"strings"

	"github.com/FlinnZee/breachhound/internal/core"
)

func init() { core.RegisterCollector(&processes{}) }

// processes gathers the running process tree with command lines and
// Authenticode signature status.
type processes struct{}

func (processes) Name() string { return "processes" }

type psProc struct {
	ProcessId       int    `json:"ProcessId"`
	ParentProcessId int    `json:"ParentProcessId"`
	Name            string `json:"Name"`
	ExecutablePath  string `json:"ExecutablePath"`
	CommandLine     string `json:"CommandLine"`
}

func (p processes) Collect(ctx *core.Context) error {
	var raw []psProc
	// Win32_Process gives pid/ppid/path/cmdline in one read-only CIM query.
	script := `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		return err
	}

	// Collect the unique executable paths and resolve all signatures in a
	// single PowerShell call rather than spawning one process per binary.
	paths := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, r := range raw {
		path := strings.TrimSpace(r.ExecutablePath)
		if path == "" || seen[strings.ToLower(path)] {
			continue
		}
		seen[strings.ToLower(path)] = true
		paths = append(paths, path)
	}
	sigs := authenticodeBatch(paths)

	for _, r := range raw {
		key := strings.ToLower(strings.TrimSpace(r.ExecutablePath))
		sig := sigs[key]
		ctx.Host.Processes = append(ctx.Host.Processes, core.Process{
			PID:       r.ProcessId,
			PPID:      r.ParentProcessId,
			Name:      r.Name,
			Path:      r.ExecutablePath,
			CmdLine:   r.CommandLine,
			Signed:    sig.valid,
			Signature: sig.signer,
		})
	}
	return nil
}

type sigResult struct {
	valid  bool
	signer string
}

// authenticodeBatch resolves Authenticode status for many files in one
// PowerShell call. Unknown/unresolvable paths are treated as unsigned.
func authenticodeBatch(paths []string) map[string]sigResult {
	out := map[string]sigResult{}
	if len(paths) == 0 {
		return out
	}

	// Build a PowerShell array literal of the paths.
	quoted := make([]string, 0, len(paths))
	for _, p := range paths {
		quoted = append(quoted, psQuote(p))
	}
	script := `@(` + strings.Join(quoted, ",") + `) | ForEach-Object {
  $s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue
  [pscustomobject]@{
    Path = $_
    Status = if ($s) { $s.Status.ToString() } else { 'Unknown' }
    Signer = if ($s -and $s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
  }
} | ConvertTo-Json -Compress -Depth 3`

	var rows []struct {
		Path   string `json:"Path"`
		Status string `json:"Status"`
		Signer string `json:"Signer"`
	}
	if err := psJSON(script, &rows); err != nil {
		return out
	}
	for _, r := range rows {
		out[strings.ToLower(strings.TrimSpace(r.Path))] = sigResult{
			valid:  r.Status == "Valid",
			signer: r.Signer,
		}
	}
	return out
}

// psQuote wraps a string as a single-quoted PowerShell literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
