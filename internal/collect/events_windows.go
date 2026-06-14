//go:build windows

package collect

import "github.com/FlinnZee/breachhound/internal/core"

func init() { core.RegisterCollector(&events{}) }

// events collects recent security-relevant Windows event-log records, preserving
// their named EventData fields for downstream (including Sigma) matching. The
// Security channel needs Administrator; without it those records are skipped.
type events struct{}

func (events) Name() string { return "events" }

func (e events) Collect(ctx *core.Context) error {
	if ctx.Config.Quick {
		ctx.Skip("events: skipped in quick mode")
		return nil
	}

	var raw []struct {
		Channel  string            `json:"Channel"`
		Provider string            `json:"Provider"`
		ID       int               `json:"Id"`
		Time     string            `json:"Time"`
		Message  string            `json:"Message"`
		Data     map[string]string `json:"Data"`
	}

	// Pull a curated set of high-signal IDs from the last two days. Each record
	// is rendered to XML so named EventData fields (Image, CommandLine, ...) are
	// preserved rather than the positional Properties array.
	script := `$logs = @{
  'Security' = 4624,4625,4688,4720,4732,4728,1102
  'System' = 7045,7036
  'Microsoft-Windows-PowerShell/Operational' = 4104
  'Microsoft-Windows-Sysmon/Operational' = 1,3,11
}
$out = foreach ($log in $logs.Keys) {
  try {
    Get-WinEvent -FilterHashtable @{ LogName=$log; Id=$logs[$log]; StartTime=(Get-Date).AddDays(-2) } -MaxEvents 300 -ErrorAction Stop | ForEach-Object {
      $data = @{}
      try {
        $x = [xml]$_.ToXml()
        foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = [string]$d.'#text' } }
      } catch {}
      $msg = if ($_.Message) { ($_.Message -split "\r?\n")[0] } else { '' }
      [pscustomobject]@{
        Channel = $_.LogName
        Provider = $_.ProviderName
        Id = [int]$_.Id
        Time = $_.TimeCreated.ToString('o')
        Message = $msg
        Data = $data
      }
    }
  } catch {}
}
$out | ConvertTo-Json -Compress -Depth 5`

	if err := psJSON(script, &raw); err != nil {
		ctx.Skip("events: " + err.Error())
		return nil
	}
	for _, r := range raw {
		ctx.Host.Events = append(ctx.Host.Events, core.Event{
			Channel:  r.Channel,
			Provider: r.Provider,
			ID:       r.ID,
			Time:     r.Time,
			Message:  r.Message,
			Data:     r.Data,
		})
	}
	return nil
}
