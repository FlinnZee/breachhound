package main

import (
	"fmt"
	"image/color"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/FlinnZee/breachhound/internal/core"
	"github.com/FlinnZee/breachhound/internal/report"
)

// ui owns the window and the mutable widgets the scan flow updates.
type ui struct {
	app fyne.App
	win fyne.Window

	hostName string
	osName   string
	elevated bool

	center *fyne.Container // swappable main content area
	quick  bool
	last   *scanResult

	runBtn    *widget.Button
	exportBtn *widget.Button
	progress  *widget.ProgressBar
	stageLbl  *widget.Label
}

// build assembles the persistent window chrome around the swappable center.
func (u *ui) build() fyne.CanvasObject {
	return container.NewBorder(u.header(), u.actions(), nil, nil, u.center)
}

func (u *ui) header() fyne.CanvasObject {
	dot := canvas.NewRectangle(hex(0x2dd4bf))
	dot.CornerRadius = 4
	brand := canvas.NewText(core.Name, hex(0xe6edf3))
	brand.TextSize = 22
	brand.TextStyle.Bold = true
	tagline := canvas.NewText("Compromise Assessment", hex(0x8b949e))
	tagline.TextSize = 12
	left := container.NewHBox(
		container.NewGridWrap(fyne.NewSize(10, 28), container.NewCenter(container.NewGridWrap(fyne.NewSize(6, 22), dot))),
		container.NewVBox(brand, tagline),
	)

	host := canvas.NewText(u.hostName, hex(0xe6edf3))
	host.TextSize = 14
	host.TextStyle.Bold = true
	host.Alignment = fyne.TextAlignTrailing
	meta := canvas.NewText(fmt.Sprintf("%s  ·  %s", u.osName, elevationText(u.elevated)), elevationColor(u.elevated))
	meta.TextSize = 12
	meta.Alignment = fyne.TextAlignTrailing
	right := container.NewVBox(host, meta)

	bar := container.NewBorder(nil, nil, left, right)
	return container.NewVBox(container.NewPadded(bar), widget.NewSeparator())
}

func (u *ui) actions() fyne.CanvasObject {
	quick := widget.NewCheck("Quick scan", func(b bool) { u.quick = b })

	u.exportBtn = widget.NewButtonWithIcon("Export report…", theme.DocumentSaveIcon(), u.exportReport)
	u.exportBtn.Disable()

	u.runBtn = widget.NewButtonWithIcon("Run Scan", theme.MediaPlayIcon(), u.startScan)
	u.runBtn.Importance = widget.HighImportance

	bar := container.NewBorder(nil, nil, quick, container.NewHBox(u.exportBtn, u.runBtn))
	return container.NewVBox(widget.NewSeparator(), container.NewPadded(bar))
}

// swap replaces the center content.
func (u *ui) swap(o fyne.CanvasObject) {
	u.center.Objects = []fyne.CanvasObject{o}
	u.center.Refresh()
}

func (u *ui) showIdle() {
	subtitle := widget.NewLabelWithStyle(
		"Read-only check of persistence, processes, and network — then a\nplain-English verdict mapped to MITRE ATT&CK.",
		fyne.TextAlignCenter, fyne.TextStyle{})

	run := widget.NewButtonWithIcon("Run Scan", theme.MediaPlayIcon(), u.startScan)
	run.Importance = widget.HighImportance

	u.swap(container.NewCenter(container.NewVBox(
		centeredText("Is this PC compromised?", 26, true, 0xe6edf3),
		subtitle,
		widget.NewLabel(""),
		container.NewCenter(run),
	)))
}

func (u *ui) showScanning() {
	u.progress = widget.NewProgressBar()
	u.stageLbl = widget.NewLabelWithStyle("Starting…", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	u.swap(container.NewCenter(container.NewVBox(
		centeredText("Scanning…", 20, true, 0xe6edf3),
		widget.NewLabel(""),
		container.NewGridWrap(fyne.NewSize(440, 16), u.progress),
		u.stageLbl,
	)))
}

func (u *ui) setProgress(frac float64, stage string) {
	if u.progress != nil {
		u.progress.SetValue(frac)
	}
	if u.stageLbl != nil {
		u.stageLbl.SetText(stage)
	}
}

func (u *ui) startScan() {
	u.runBtn.Disable()
	u.exportBtn.Disable()
	u.showScanning()

	total := stageCount()
	if total == 0 {
		total = 1
	}
	count := 0
	go func() {
		res := runScan(u.quick, func(phase, name string) {
			count++
			d := count
			fyne.Do(func() { u.setProgress(float64(d)/float64(total), stageVerb(phase)+" "+name) })
		})
		fyne.Do(func() {
			u.last = &res
			u.runBtn.Enable()
			u.exportBtn.Enable()
			u.showResults(res)
		})
	}()
}

func (u *ui) showResults(res scanResult) {
	top := container.NewVBox(verdictBanner(res.Result), summaryLine(res.Result))
	if note := skippedNote(res.Result); note != nil {
		top.Add(note)
	}

	var body fyne.CanvasObject
	if len(res.Result.Findings) == 0 {
		body = container.NewCenter(centeredText("No findings recorded.", 14, false, 0x8b949e))
	} else {
		body = findingsSplit(res.Result)
	}
	u.swap(container.NewBorder(top, nil, nil, nil, container.NewPadded(body)))
}

func (u *ui) exportReport() {
	if u.last == nil {
		return
	}
	dialog.ShowFolderOpen(func(dir fyne.ListableURI, err error) {
		if err != nil || dir == nil {
			return
		}
		path := dir.Path()
		var wrote []string
		if p, e := report.WriteJSON(path, u.last.Host, u.last.Result); e == nil {
			wrote = append(wrote, p)
		}
		if p, e := report.WriteHTML(path, u.last.Host, u.last.Result); e == nil {
			wrote = append(wrote, p)
		}
		if len(wrote) == 0 {
			dialog.ShowError(fmt.Errorf("could not write report to %s", path), u.win)
			return
		}
		dialog.ShowInformation("Report saved", strings.Join(wrote, "\n"), u.win)
	}, u.win)
}

// --- view builders ---

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

func findingsSplit(r core.Result) fyne.CanvasObject {
	detail := widget.NewRichTextFromMarkdown(
		"### Select a finding\n\nPick an item on the left to see its evidence and ATT&CK mapping.")
	detail.Wrapping = fyne.TextWrapWord
	show := func(f core.Finding) { detail.ParseMarkdown(findingMarkdown(f)) }

	groups := report.GroupByTactic(r.Findings)
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
	chip := canvas.NewRectangle(severityColor(f.Severity))
	chip.CornerRadius = 3
	chipBox := container.NewGridWrap(fyne.NewSize(12, 12), chip)

	btn := widget.NewButton(f.Title, func() { onTap(f) })
	btn.Alignment = widget.ButtonAlignLeading
	btn.Importance = widget.LowImportance

	return container.NewBorder(nil, nil, container.NewCenter(chipBox), nil, btn)
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

// --- small helpers ---

func centeredText(s string, size float32, bold bool, rgb uint32) *canvas.Text {
	t := canvas.NewText(s, hex(rgb))
	t.TextSize = size
	t.TextStyle.Bold = bold
	t.Alignment = fyne.TextAlignCenter
	return t
}

func sortedKeys(m map[string][]core.Finding) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func stageVerb(phase string) string {
	switch phase {
	case "collect":
		return "Collecting"
	case "detect":
		return "Detecting"
	default:
		return phase
	}
}

func elevationText(elevated bool) string {
	if elevated {
		return "Administrator"
	}
	return "Standard user — some checks skipped"
}

func elevationColor(elevated bool) color.Color {
	if elevated {
		return hex(0x5ee08a)
	}
	return hex(0xf2cc60)
}

func verdictBlurb(v core.Verdict) string {
	switch v {
	case core.VerdictCompromised:
		return "We found strong indicators that this machine may be compromised. Treat it as suspect and investigate the findings below now."
	case core.VerdictReview:
		return "Some things look unusual and deserve a closer look by a person. They are not proof of a hack on their own."
	default:
		return "No strong signs of compromise were found in what we could examine. This is reassuring, but not a guarantee."
	}
}
