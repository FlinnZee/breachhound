// Command breachhound-gui is the desktop front-end for BreachHound. It drives
// the same read-only collect/detect/score pipeline as the CLI and presents the
// verdict and evidence in a native window.
package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"

	"github.com/FlinnZee/breachhound/internal/core"
)

func main() {
	a := app.New()
	a.Settings().SetTheme(newBreachTheme())

	w := a.NewWindow(core.Name + " — Compromise Assessment")
	w.Resize(fyne.NewSize(1040, 720))

	name, osName, elevated := quickHostInfo()
	u := &ui{
		app:      a,
		win:      w,
		hostName: name,
		osName:   osName,
		elevated: elevated,
		center:   container.NewStack(),
	}
	w.SetContent(u.build())
	u.showIdle()
	w.ShowAndRun()
}
