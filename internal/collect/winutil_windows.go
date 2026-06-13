//go:build windows

package collect

import (
	"encoding/json"
	"os/exec"
)

// psJSON runs a PowerShell snippet that emits JSON and decodes it into out.
// All snippets used here are strictly read-only queries.
func psJSON(script string, out any) error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	data, err := cmd.Output()
	if err != nil {
		return err
	}
	// PowerShell emits nothing for an empty result; treat that as no data.
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}
