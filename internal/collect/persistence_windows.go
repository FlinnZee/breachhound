//go:build windows

package collect

import (
	"strings"

	"github.com/FlinnZee/breachhound/internal/core"
)

func init() { core.RegisterCollector(&persistence{}) }

// persistence gathers common autostart extensibility points (ASEPs): Run/
// RunOnce registry keys, services, and scheduled tasks.
type persistence struct{}

func (persistence) Name() string { return "persistence" }

func (p persistence) Collect(ctx *core.Context) error {
	p.collectRunKeys(ctx)
	p.collectServices(ctx)
	p.collectScheduledTasks(ctx)
	p.collectWinlogon(ctx)
	p.collectAppInitDLLs(ctx)
	p.collectIFEO(ctx)
	p.collectStartupFolders(ctx)
	p.collectWMISubscriptions(ctx)
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

// collectWinlogon reads the Winlogon Shell/Userinit values, which malware
// commonly appends to for persistence (ATT&CK T1547.004).
func (p persistence) collectWinlogon(ctx *core.Context) {
	const key = `HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	var v struct {
		Shell    string `json:"Shell"`
		Userinit string `json:"Userinit"`
	}
	script := `$i = Get-ItemProperty -Path '` + key + `' -ErrorAction SilentlyContinue
[pscustomobject]@{ Shell=[string]$i.Shell; Userinit=[string]$i.Userinit } | ConvertTo-Json -Compress`
	if err := psJSON(script, &v); err != nil {
		ctx.Skip("persistence winlogon: " + err.Error())
		return
	}
	for name, cmd := range map[string]string{"Shell": v.Shell, "Userinit": v.Userinit} {
		if strings.TrimSpace(cmd) == "" {
			continue
		}
		ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
			Type:     "winlogon",
			Name:     name,
			Command:  cmd,
			Location: key,
		})
	}
}

// collectAppInitDLLs reads AppInit_DLLs, an old but still-abused injection-based
// persistence mechanism (ATT&CK T1546.010).
func (p persistence) collectAppInitDLLs(ctx *core.Context) {
	keys := []string{
		`HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows`,
		`HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	}
	for _, key := range keys {
		var v struct {
			AppInitDLLs string `json:"AppInit_DLLs"`
		}
		script := `$i = Get-ItemProperty -Path '` + key + `' -ErrorAction SilentlyContinue
[pscustomobject]@{ 'AppInit_DLLs'=[string]$i.'AppInit_DLLs' } | ConvertTo-Json -Compress`
		if err := psJSON(script, &v); err != nil {
			continue
		}
		if strings.TrimSpace(v.AppInitDLLs) == "" {
			continue
		}
		ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
			Type:     "appinit_dll",
			Name:     "AppInit_DLLs",
			Command:  v.AppInitDLLs,
			Location: key,
		})
	}
}

// collectIFEO enumerates Image File Execution Options entries that set a
// Debugger, a common hijack/persistence trick (ATT&CK T1546.012).
func (p persistence) collectIFEO(ctx *core.Context) {
	var raw []struct {
		Image    string `json:"Image"`
		Debugger string `json:"Debugger"`
	}
	script := `Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
  $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
  if ($d) { [pscustomobject]@{ Image=$_.PSChildName; Debugger=[string]$d } }
} | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		ctx.Skip("persistence ifeo: " + err.Error())
		return
	}
	for _, e := range raw {
		ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
			Type:     "ifeo_debugger",
			Name:     e.Image,
			Command:  e.Debugger,
			Location: `IFEO\` + e.Image,
		})
	}
}

// collectStartupFolders lists shortcuts/executables dropped into the per-user
// and all-users Startup folders (ATT&CK T1547.001).
func (p persistence) collectStartupFolders(ctx *core.Context) {
	var raw []struct {
		Name string `json:"Name"`
		Path string `json:"Path"`
	}
	script := `$dirs = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
$dirs | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
  Get-ChildItem -LiteralPath $_ -File -ErrorAction SilentlyContinue
} | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Path=$_.FullName } } | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		ctx.Skip("persistence startup-folder: " + err.Error())
		return
	}
	for _, f := range raw {
		ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
			Type:     "startup_folder",
			Name:     f.Name,
			Command:  f.Path,
			Location: "Startup",
		})
	}
}

// collectWMISubscriptions reads permanent WMI event subscriptions, a stealthy
// fileless persistence mechanism (ATT&CK T1546.003).
func (p persistence) collectWMISubscriptions(ctx *core.Context) {
	var raw []struct {
		Name        string `json:"Name"`
		CommandLine string `json:"CommandLineTemplate"`
		Consumer    string `json:"Consumer"`
	}
	script := `Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ Name=$_.Name; CommandLineTemplate=[string]$_.CommandLineTemplate; Consumer=$_.CimClass.CimClassName }
} | ConvertTo-Json -Compress -Depth 3`
	if err := psJSON(script, &raw); err != nil {
		ctx.Skip("persistence wmi-subscription: " + err.Error())
		return
	}
	for _, w := range raw {
		ctx.Host.Persistence = append(ctx.Host.Persistence, core.PersistenceItem{
			Type:     "wmi_subscription",
			Name:     w.Name,
			Command:  w.CommandLine,
			Location: "root\\subscription:" + w.Consumer,
		})
	}
}
