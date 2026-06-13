//go:build windows

package collect

import "github.com/FlinnZee/breachhound/internal/core"

func init() { core.RegisterCollector(&persistence{}) }

// persistence gathers common autostart extensibility points (ASEPs): Run/
// RunOnce registry keys, services, and scheduled tasks.
type persistence struct{}

func (persistence) Name() string { return "persistence" }

func (p persistence) Collect(ctx *core.Context) error {
	p.collectRunKeys(ctx)
	p.collectServices(ctx)
	p.collectScheduledTasks(ctx)
	return nil
}

func (p persistence) collectRunKeys(ctx *core.Context) {
	runKeys := []string{
		`HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	for _, key := range runKeys {
		var entries map[string]string
		script := `$p='` + key + `'; if (Test-Path $p) {
  $i = Get-ItemProperty -Path $p
  $o = @{}; $i.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $o[$_.Name] = [string]$_.Value }
  $o | ConvertTo-Json -Compress
}`
		if err := psJSON(script, &entries); err != nil {
			ctx.Skip("persistence run-key " + key + ": " + err.Error())
			continue
		}
		for name, cmd := range entries {
			ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
				Type:     "run_key",
				Name:     name,
				Command:  cmd,
				Location: key,
			})
		}
	}
}

func (p persistence) collectServices(ctx *core.Context) {
	var raw []struct {
		Name     string `json:"Name"`
		PathName string `json:"PathName"`
		StartMode string `json:"StartMode"`
	}
	script := `Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		ctx.Skip("persistence services: " + err.Error())
		return
	}
	for _, s := range raw {
		ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
			Type:     "service",
			Name:     s.Name,
			Command:  s.PathName,
			Location: "Win32_Service:" + s.StartMode,
		})
	}
}

func (p persistence) collectScheduledTasks(ctx *core.Context) {
	var raw []struct {
		TaskName string `json:"TaskName"`
		TaskPath string `json:"TaskPath"`
		Action   string `json:"Action"`
	}
	script := `Get-ScheduledTask | ForEach-Object {
  [pscustomobject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; Action=($_.Actions.Execute -join ';') }
} | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		ctx.Skip("persistence scheduled-tasks: " + err.Error())
		return
	}
	for _, t := range raw {
		ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
			Type:     "scheduled_task",
			Name:     t.TaskName,
			Command:  t.Action,
			Location: t.TaskPath,
		})
	}
}
