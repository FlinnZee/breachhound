package main

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/FlinnZee/breachhound/internal/core"
	"github.com/FlinnZee/breachhound/internal/report"
)

// emptyState is shown in a section before a scan has produced data.
func (u *ui) emptyState(title, sub string, showRun bool) fyne.CanvasObject {
	items := []fyne.CanvasObject{centeredText(title, 22, true, 0xe6edf3)}
	if sub != "" {
		items = append(items, widget.NewLabelWithStyle(sub, fyne.TextAlignCenter, fyne.TextStyle{}))
	}
	if showRun {
		run := widget.NewButtonWithIcon("Run Scan", theme.MediaPlayIcon(), u.startScan)
		run.Importance = widget.HighImportance
		items = append(items, widget.NewLabel(""), container.NewCenter(run))
	}
	return container.NewCenter(container.NewVBox(items...))
}

func (u *ui) dashboardView() fyne.CanvasObject {
	if u.last == nil {
		return u.emptyState("Is this PC compromised?",
			"Run a read-only scan to get a verdict and surface every artifact.", true)
	}
	res := u.last
	r := res.Result
	crit, high, med, low := severityCounts(r.Findings)

	sevRow := container.NewHBox(
		statCard(strconv.Itoa(crit), "Critical", severityColor(core.SevCritical)),
		statCard(strconv.Itoa(high), "High", severityColor(core.SevHigh)),
		statCard(strconv.Itoa(med), "Medium", severityColor(core.SevMedium)),
		statCard(strconv.Itoa(low), "Low", severityColor(core.SevLow)),
	)
	artRow := container.NewHBox(
		statCard(strconv.Itoa(len(res.Host.Processes)), "Processes", hex(0x2dd4bf)),
		statCard(strconv.Itoa(len(res.Host.Connections)), "Connections", hex(0x2dd4bf)),
		statCard(strconv.Itoa(len(res.Host.Persistence)), "Persistence", hex(0x2dd4bf)),
		statCard(strconv.Itoa(unsignedCount(res.Host.Processes)), "Unsigned", hex(0xff8c42)),
	)
	cards := container.NewVBox(sevRow, artRow)

	row := container.NewBorder(nil, nil, container.NewPadded(riskGauge(r.RiskScore, r.Verdict)), nil,
		container.NewPadded(cards))

	content := container.NewVBox()
	if res.Host.Hostname == "DEMO-HOST" {
		content.Add(demoNotice())
	}
	content.Add(verdictBanner(r))
	content.Add(summaryLine(r))
	content.Add(scanMeta(res))
	content.Add(widget.NewSeparator())
	content.Add(row)
	if note := skippedNote(r); note != nil {
		content.Add(note)
	}
	return container.NewScroll(content)
}

func demoNotice() fyne.CanvasObject {
	bg := canvas.NewRectangle(hex(0x3d340f))
	bg.CornerRadius = 8
	txt := canvas.NewText("DEMO DATA — sample findings, not a real scan of this machine", hex(0xf2cc60))
	txt.TextStyle.Bold = true
	txt.TextSize = 13
	return container.NewPadded(container.NewStack(bg, container.NewPadded(txt)))
}

func scanMeta(res *scanResult) fyne.CanvasObject {
	when := res.Host.CollectedAt.Format("2006-01-02 15:04:05")
	txt := fmt.Sprintf("Scanned %s · %s · completed in %s",
		res.Host.Hostname, when, res.Duration.Round(time.Millisecond))
	return container.NewPadded(widget.NewLabelWithStyle(txt, fyne.TextAlignLeading, fyne.TextStyle{Italic: true}))
}

func (u *ui) findingsView() fyne.CanvasObject {
	if u.last == nil {
		return u.emptyState("No scan yet", "Run a scan to see findings.", true)
	}
	all := u.last.Result.Findings
	if len(all) == 0 {
		return container.NewCenter(centeredText("No findings recorded.", 16, false, 0x8b949e))
	}

	body := container.NewStack()
	render := func(sev string) {
		fs := filterBySeverity(all, sev)
		if len(fs) == 0 {
			body.Objects = []fyne.CanvasObject{container.NewCenter(centeredText("No findings at this level.", 14, false, 0x8b949e))}
		} else {
			body.Objects = []fyne.CanvasObject{findingsSplit(fs)}
		}
		body.Refresh()
	}

	sel := widget.NewSelect([]string{"All", "Critical", "High", "Medium", "Low", "Info"}, render)
	sel.SetSelected("All")
	top := container.NewBorder(nil, nil, widget.NewLabelWithStyle("Severity", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), nil, sel)

	return container.NewBorder(container.NewPadded(top), nil, nil, nil, container.NewPadded(body))
}

func filterBySeverity(fs []core.Finding, sev string) []core.Finding {
	if sev == "" || sev == "All" {
		return fs
	}
	var out []core.Finding
	for _, f := range fs {
		if strings.EqualFold(f.Severity.String(), sev) {
			out = append(out, f)
		}
	}
	return out
}

func (u *ui) processesView() fyne.CanvasObject {
	if u.last == nil {
		return u.emptyState("No scan yet", "Run a scan to list running processes.", true)
	}
	return container.NewPadded(newDataTable(
		[]string{"PID", "PPID", "Name", "Signature", "Path", "Command line"},
		[]float32{64, 64, 170, 90, 300, 520},
		processRows(u.last.Host),
	))
}

func (u *ui) networkView() fyne.CanvasObject {
	if u.last == nil {
		return u.emptyState("No scan yet", "Run a scan to list network connections.", true)
	}
	return container.NewPadded(newDataTable(
		[]string{"Proto", "Local", "Remote", "State", "PID", "Process"},
		[]float32{60, 200, 200, 120, 64, 180},
		connRows(u.last.Host),
	))
}

func (u *ui) persistenceView() fyne.CanvasObject {
	if u.last == nil {
		return u.emptyState("No scan yet", "Run a scan to list persistence entries.", true)
	}
	return container.NewPadded(newDataTable(
		[]string{"Type", "Name", "Command", "Location"},
		[]float32{140, 200, 420, 280},
		persistenceRows(u.last.Host),
	))
}

func (u *ui) accountsView() fyne.CanvasObject {
	if u.last == nil {
		return u.emptyState("No scan yet", "Run a scan to list local accounts.", true)
	}
	return container.NewPadded(newDataTable(
		[]string{"User", "Admin", "Enabled", "Last logon", "SID"},
		[]float32{180, 80, 90, 150, 320},
		accountRows(u.last.Host),
	))
}

// --- shared finding/result builders ---

func verdictBanner(r core.Result) fyne.CanvasObject {
	bg := canvas.NewRectangle(verdictColor(r.Verdict))
	bg.CornerRadius = 12

	v := canvas.NewText(string(r.Verdict), color.White)
	v.TextSize = 28
	v.TextStyle.Bold = true
	score := canvas.NewText(fmt.Sprintf("Risk score   %d / 100", r.RiskScore), color.White)
	score.TextSize = 14

	inner := container.NewPadded(container.NewPadded(container.NewVBox(v, score)))
	return container.NewPadded(container.NewStack(bg, inner))
}

func summaryLine(r core.Result) fyne.CanvasObject {
	lbl := widget.NewLabel(verdictBlurb(r.Verdict))
	lbl.Wrapping = fyne.TextWrapWord
	return container.NewPadded(lbl)
}

func skippedNote(r core.Result) fyne.CanvasObject {
	if len(r.Skipped) == 0 {
		return nil
	}
	txt := fmt.Sprintf("Note: %d check(s) were skipped (often needs Administrator).", len(r.Skipped))
	return container.NewPadded(widget.NewLabelWithStyle(txt, fyne.TextAlignLeading, fyne.TextStyle{Italic: true}))
}

func findingsSplit(findings []core.Finding) fyne.CanvasObject {
	detail := widget.NewRichTextFromMarkdown(
		"### Select a finding\n\nPick an item on the left to see its evidence and ATT&CK mapping.")
	detail.Wrapping = fyne.TextWrapWord
	show := func(f core.Finding) { detail.ParseMarkdown(findingMarkdown(f)) }

	groups := report.GroupByTactic(findings)
	acc := widget.NewAccordion()
	acc.MultiOpen = true
	for _, t := range sortedKeys(groups) {
		fs := groups[t]
		rows := container.NewVBox()
		for _, f := range fs {
			rows.Add(findingRow(f, show))
		}
		item := widget.NewAccordionItem(fmt.Sprintf("%s  (%d)", t, len(fs)), rows)
		item.Open = true
		acc.Append(item)
	}

	split := container.NewHSplit(container.NewScroll(acc), container.NewScroll(detail))
	split.Offset = 0.46
	return split
}

func findingRow(f core.Finding, onTap func(core.Finding)) fyne.CanvasObject {
	btn := widget.NewButton(f.Title, func() { onTap(f) })
	btn.Alignment = widget.ButtonAlignLeading
	btn.Importance = widget.LowImportance
	return container.NewBorder(nil, nil, container.NewCenter(severityChip(f.Severity)), nil, btn)
}

func findingMarkdown(f core.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n", f.Title)
	fmt.Fprintf(&b, "**Severity:** %s  •  **Confidence:** %s\n\n", f.Severity, f.Confidence)
	if f.Technique != "" || f.Tactic != "" {
		fmt.Fprintf(&b, "**ATT&CK:** %s %s\n\n", f.Technique, f.Tactic)
	}
	if f.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", f.Description)
	}
	if len(f.Evidence) > 0 {
		b.WriteString("**Evidence**\n\n")
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "- `%s`\n", e)
		}
	}
	return b.String()
}

// --- row extractors over the collected HostModel ---

func processRows(h *core.HostModel) [][]string {
	rows := make([][]string, 0, len(h.Processes))
	for _, p := range h.Processes {
		sig := "unsigned"
		if p.Signed {
			sig = "signed"
		}
		rows = append(rows, []string{
			strconv.Itoa(p.PID), strconv.Itoa(p.PPID), p.Name, sig, p.Path, p.CmdLine,
		})
	}
	return rows
}

func connRows(h *core.HostModel) [][]string {
	rows := make([][]string, 0, len(h.Connections))
	for _, c := range h.Connections {
		local := c.LocalAddr
		if c.LocalPort != 0 {
			local = fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort)
		}
		remote := c.RemoteAddr
		if c.RemotePort != 0 {
			remote = fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort)
		}
		rows = append(rows, []string{
			c.Proto, local, remote, c.State, strconv.Itoa(c.PID), c.ProcessName,
		})
	}
	return rows
}

func persistenceRows(h *core.HostModel) [][]string {
	rows := make([][]string, 0, len(h.Persistence))
	for _, p := range h.Persistence {
		rows = append(rows, []string{p.Type, p.Name, p.Command, p.Location})
	}
	return rows
}

func accountRows(h *core.HostModel) [][]string {
	rows := make([][]string, 0, len(h.Users))
	for _, u := range h.Users {
		rows = append(rows, []string{u.Name, yesNo(u.Admin), yesNo(u.Enabled), u.LastLogon, u.SID})
	}
	return rows
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
