# BreachHound

**Run it on your Windows PC and it tells you if you've been hacked.**

BreachHound is a read-only Windows **compromise-assessment** tool. It collects
forensic artifacts, runs a layered detection engine over them, and produces both
a plain-English verdict and a detailed technical report mapped to MITRE ATT&CK.

It is a **defensive / blue-team** tool. It only inspects and reports — it never
modifies or "cleans" the system. For use on systems you own or are authorized to
assess.

## What it does

```
collect  →  detect  →  score  →  report
artifacts   rules      risk      verdict + JSON/HTML
```

- **Collect** — persistence (Run keys, services, scheduled tasks), processes
  (tree, signatures, suspicious paths), and network connections with their
  owning processes.
- **Detect** — behavioral heuristics (unsigned binaries in temp, LOLBins with
  download args, document apps spawning shells, encoded PowerShell, persistence
  in user-writable paths) and known-bad IOC matching (IPs, domains).
- **Score** — findings roll up into a 0–100 risk score and a verdict.
- **Report** — a plain-English verdict plus `report.json` and a styled
  `report.html` grouped by ATT&CK tactic.

## Verdicts

| Verdict | Meaning |
|---|---|
| `LOOKS CLEAN` | No strong signs of compromise in what could be examined. |
| `NEEDS REVIEW` | Some unusual things a person should look at. |
| `LIKELY COMPROMISED` | Strong indicators of compromise — investigate now. |

## Build

BreachHound is pure Go and ships as a single portable `.exe`.

```sh
# Native build
go build ./cmd/breachhound

# Cross-compile to Windows from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o breachhound.exe ./cmd/breachhound
```

## Run

```
breachhound.exe                 # full scan, writes report.json + report.html
breachhound.exe --quick         # faster, lighter scan
breachhound.exe --out C:\triage # choose output directory
breachhound.exe --format json   # json only
```

Many artifacts require **Administrator**. BreachHound detects elevation, degrades
gracefully, and clearly lists any checks it had to skip.

## Status

Phase 1 (MVP): core pipeline, three collectors, heuristics + IOC detectors,
scoring, JSON/HTML reports. Planned next: Sigma over event logs, YARA (optional
build tag), Amcache/Shimcache/Prefetch, and a fleet (agent + server) mode.

## Tests

```sh
go test ./...
```

---
*Author: TK NiRMAL. Sibling to WebStrike. Defensive use only.*
