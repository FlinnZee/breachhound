package main

import (
	"fmt"
	"image/color"
	"sort"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/FlinnZee/breachhound/internal/core"
)

// riskGauge draws a circular risk badge: a ring colored by verdict with the
// 0–100 risk score in the middle. Built from two circles (outer = verdict
// color, inner = background) so it renders reliably across platforms.
func riskGauge(risk int, v core.Verdict) fyne.CanvasObject {
	outer := canvas.NewCircle(verdictColor(v))
	hole := canvas.NewCircle(hex(0x0e1116)) // matches window background

	num := canvas.NewText(strconv.Itoa(risk), hex(0xffffff))
	num.TextSize = 38
	num.TextStyle.Bold = true
	num.Alignment = fyne.TextAlignCenter
	cap := canvas.NewText("/ 100 risk", hex(0x9fb0c0))
	cap.TextSize = 11
	cap.Alignment = fyne.TextAlignCenter
	label := container.NewCenter(container.NewVBox(num, cap))

	ring := container.NewStack(
		container.NewGridWrap(fyne.NewSize(176, 176), outer),
		container.NewCenter(container.NewGridWrap(fyne.NewSize(150, 150), hole)),
		label,
	)
	return container.NewGridWrap(fyne.NewSize(176, 176), ring)
}

// statCard is a small rounded card showing a value over a label.
func statCard(value, label string, accent color.Color) fyne.CanvasObject {
	bg := canvas.NewRectangle(hex(0x161b22))
	bg.CornerRadius = 10
	bg.StrokeColor = hex(0x30363d)
	bg.StrokeWidth = 1

	val := canvas.NewText(value, accent)
	val.TextSize = 26
	val.TextStyle.Bold = true
	lab := canvas.NewText(label, hex(0x8b949e))
	lab.TextSize = 12

	inner := container.NewPadded(container.NewVBox(val, lab))
	return container.NewGridWrap(fyne.NewSize(158, 84), container.NewStack(bg, inner))
}

// severityChip is a small rounded color swatch for a severity level.
func severityChip(s core.Severity) fyne.CanvasObject {
	c := canvas.NewRectangle(severityColor(s))
	c.CornerRadius = 3
	return container.NewGridWrap(fyne.NewSize(12, 12), c)
}

// newDataTable builds a searchable table over rows. headers/widths define the
// columns; a search box filters rows by case-insensitive substring.
func newDataTable(headers []string, widths []float32, allRows [][]string) fyne.CanvasObject {
	filtered := allRows

	table := widget.NewTable(
		func() (int, int) { return len(filtered), len(headers) },
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.Truncation = fyne.TextTruncateEllipsis
			return l
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			if id.Row < len(filtered) && id.Col < len(headers) {
				o.(*widget.Label).SetText(filtered[id.Row][id.Col])
			}
		},
	)
	table.ShowHeaderRow = true
	table.CreateHeader = func() fyne.CanvasObject {
		return widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	}
	table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		l := o.(*widget.Label)
		if id.Row == -1 && id.Col >= 0 && id.Col < len(headers) {
			l.SetText(headers[id.Col])
		} else {
			l.SetText("")
		}
	}
	for i, w := range widths {
		table.SetColumnWidth(i, w)
	}

	search := widget.NewEntry()
	search.SetPlaceHolder("Search…")
	search.OnChanged = func(q string) {
		q = strings.ToLower(strings.TrimSpace(q))
		if q == "" {
			filtered = allRows
		} else {
			filtered = nil
			for _, r := range allRows {
				if rowMatches(r, q) {
					filtered = append(filtered, r)
				}
			}
		}
		table.Refresh()
	}

	count := widget.NewLabel("")
	updateCount := func() { count.SetText(fmt.Sprintf("%d rows", len(filtered))) }
	updateCount()
	prev := search.OnChanged
	search.OnChanged = func(q string) { prev(q); updateCount() }

	top := container.NewBorder(nil, nil, nil, count, search)
	return container.NewBorder(top, nil, nil, nil, table)
}

func rowMatches(row []string, q string) bool {
	for _, c := range row {
		if strings.Contains(strings.ToLower(c), q) {
			return true
		}
	}
	return false
}

// --- small shared helpers ---

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

func severityCounts(fs []core.Finding) (crit, high, med, low int) {
	for _, f := range fs {
		switch f.Severity {
		case core.SevCritical:
			crit++
		case core.SevHigh:
			high++
		case core.SevMedium:
			med++
		case core.SevLow:
			low++
		}
	}
	return
}

func unsignedCount(ps []core.Process) int {
	n := 0
	for _, p := range ps {
		if !p.Signed && p.Path != "" {
			n++
		}
	}
	return n
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
	return "Standard user"
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
		return "We found strong indicators that this machine may be compromised. Treat it as suspect and investigate the findings now."
	case core.VerdictReview:
		return "Some things look unusual and deserve a closer look by a person. They are not proof of a hack on their own."
	default:
		return "No strong signs of compromise were found in what we could examine. This is reassuring, but not a guarantee."
	}
}
