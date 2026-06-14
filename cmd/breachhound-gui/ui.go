package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/FlinnZee/breachhound/internal/collect"
	"github.com/FlinnZee/breachhound/internal/core"
	"github.com/FlinnZee/breachhound/internal/report"
)

// navOrder defines the sidebar sections, in order.
var navOrder = []struct {
	id, label string
	icon      fyne.Resource
}{
	{"dashboard", "Dashboard", theme.HomeIcon()},
	{"findings", "Findings", theme.WarningIcon()},
	{"processes", "Processes", theme.ComputerIcon()},
	{"network", "Network", theme.MailSendIcon()},
	{"persistence", "Persistence", theme.StorageIcon()},
	{"accounts", "Accounts", theme.AccountIcon()},
}

// ui owns the window and the mutable widgets the scan flow updates.
type ui struct {
	app fyne.App
	win fyne.Window

	hostName string
	osName   string
	elevated bool

	quick bool
	last  *scanResult

	content    *fyne.Container // swappable main content area
	active     string
	navButtons map[string]*widget.Button

	runBtn    *widget.Button
	exportBtn *widget.Button
	progress  *widget.ProgressBar
	stageLbl  *widget.Label
}

// build assembles the sidebar + main content shell.
func (u *ui) build() fyne.CanvasObject {
	u.content = container.NewStack()
	sidebar := u.buildSidebar()
	return container.NewBorder(nil, nil, container.NewHBox(sidebar, widget.NewSeparator()), nil, u.content)
}

func (u *ui) buildSidebar() fyne.CanvasObject {
	accent := canvas.NewRectangle(hex(0x2dd4bf))
	accent.CornerRadius = 2
	brandText := canvas.NewText(core.Name, hex(0xe6edf3))
	brandText.TextSize = 20
	brandText.TextStyle.Bold = true
	brand := container.NewHBox(container.NewGridWrap(fyne.NewSize(4, 22), accent), brandText)
	top := container.NewVBox(container.NewPadded(brand), widget.NewSeparator())

	u.navButtons = map[string]*widget.Button{}
	navBox := container.NewVBox()
	for _, it := range navOrder {
		id := it.id
		b := widget.NewButtonWithIcon(it.label, it.icon, func() { u.selectView(id) })
		b.Alignment = widget.ButtonAlignLeading
		b.Importance = widget.LowImportance
		u.navButtons[id] = b
		navBox.Add(b)
	}

	host := canvas.NewText(u.hostName, hex(0xe6edf3))
	host.TextSize = 13
	host.TextStyle.Bold = true
	meta := canvas.NewText(fmt.Sprintf("%s · %s", u.osName, elevationText(u.elevated)), elevationColor(u.elevated))
	meta.TextSize = 11

	u.runBtn = widget.NewButtonWithIcon("Run Scan", theme.MediaPlayIcon(), u.startScan)
	u.runBtn.Importance = widget.HighImportance
	u.exportBtn = widget.NewButtonWithIcon("Export report…", theme.DocumentSaveIcon(), u.exportReport)
	u.exportBtn.Disable()
	quick := widget.NewCheck("Quick scan", func(b bool) { u.quick = b })

	controls := []fyne.CanvasObject{host, meta}
	if !u.elevated {
		el := widget.NewButtonWithIcon("Run as Administrator", theme.WarningIcon(), u.elevate)
		el.Importance = widget.WarningImportance
		controls = append(controls, el)
	}
	about := widget.NewButtonWithIcon("About", theme.InfoIcon(), u.showAbout)
	about.Importance = widget.LowImportance
	controls = append(controls, widget.NewLabel(""), u.runBtn, u.exportBtn, quick, about)

	credit := canvas.NewText(fmt.Sprintf("v%s  ·  by %s", core.Version, core.Author), hex(0x6e7681))
	credit.TextSize = 10

	bottom := container.NewVBox(
		widget.NewSeparator(),
		container.NewPadded(container.NewVBox(controls...)),
		widget.NewSeparator(),
		container.NewPadded(credit),
	)

	return container.NewBorder(top, bottom, nil, nil, container.NewVScroll(navBox))
}

func (u *ui) selectView(id string) {
	u.active = id
	for nid, b := range u.navButtons {
		if nid == id {
			b.Importance = widget.HighImportance
		} else {
			b.Importance = widget.LowImportance
		}
		b.Refresh()
	}
	u.content.Objects = []fyne.CanvasObject{u.viewContent(id)}
	u.content.Refresh()
}

func (u *ui) viewContent(id string) fyne.CanvasObject {
	switch id {
	case "findings":
		return u.findingsView()
	case "processes":
		return u.processesView()
	case "network":
		return u.networkView()
	case "persistence":
		return u.persistenceView()
	case "accounts":
		return u.accountsView()
	default:
		return u.dashboardView()
	}
}

func (u *ui) startScan() {
	u.runBtn.Disable()
	u.exportBtn.Disable()

	u.progress = widget.NewProgressBar()
	u.stageLbl = widget.NewLabelWithStyle("Starting…", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})
	u.content.Objects = []fyne.CanvasObject{container.NewCenter(container.NewVBox(
		centeredText("Scanning…", 20, true, 0xe6edf3),
		widget.NewLabel(""),
		container.NewGridWrap(fyne.NewSize(440, 16), u.progress),
		u.stageLbl,
	))}
	u.content.Refresh()

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
			u.selectView("dashboard")
		})
	}()
}

func (u *ui) setProgress(frac float64, stage string) {
	if u.progress != nil {
		u.progress.SetValue(frac)
	}
	if u.stageLbl != nil {
		u.stageLbl.SetText(stage)
	}
}

func (u *ui) elevate() {
	if err := collect.Relaunch(); err != nil {
		dialog.ShowInformation("Could not elevate",
			"BreachHound could not relaunch with Administrator rights. You can also right-click the app and choose \"Run as administrator\".",
			u.win)
		return
	}
	// The elevated instance is starting; close this unelevated one.
	u.app.Quit()
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
		dialog.ShowInformation("Report saved", join(wrote), u.win)
		openFolder(path)
	}, u.win)
}

func (u *ui) showAbout() {
	msg := fmt.Sprintf(
		"%s  v%s\nby %s\n\nA read-only Windows compromise-assessment tool.\nIt inspects and reports — it never modifies the system.\nFor defensive, authorized use only.\n\ngithub.com/FlinnZee/breachhound",
		core.Name, core.Version, core.Author)
	dialog.ShowInformation("About "+core.Name, msg, u.win)
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += "\n"
		}
		out += v
	}
	return out
}
