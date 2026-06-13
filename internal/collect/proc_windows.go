//go:build windows

package collect

import (
	"strings"

	"github.com/FlinnZee/breachhound/internal/core"
)

func init() { core.RegisterCollector(&processes{}) }

// processes gathers the running process tree with command lines and (best
// effort) Authenticode signature status.
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
	for _, r := range raw {
		signed, signer := authenticode(r.ExecutablePath)
		ctx.Host.Processes = append(ctx.Host.Processes, core.Process{
			PID:       r.ProcessId,
			PPID:      r.ParentProcessId,
			Name:      r.Name,
			Path:      r.ExecutablePath,
			CmdLine:   r.CommandLine,
			Signed:    signed,
			Signature: signer,
		})
	}
	return nil
}

// authenticode checks a file's signature status. Errors degrade to unsigned.
func authenticode(path string) (bool, string) {
	if strings.TrimSpace(path) == "" {
		return false, ""
	}
	var res struct {
		Status string `json:"Status"`
		Signer string `json:"SignerCertificate"`
	}
	script := `$s = Get-AuthenticodeSignature -LiteralPath ` + psQuote(path) +
		`; [pscustomobject]@{Status=$s.Status.ToString();SignerCertificate=$s.SignerCertificate.Subject} | ConvertTo-Json -Compress`
	if err := psJSON(script, &res); err != nil {
		return false, ""
	}
	return res.Status == "Valid", res.Signer
}

// psQuote wraps a string as a single-quoted PowerShell literal.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
