package main

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

//go:embed assets/icon.svg
var iconSVG []byte

// appIcon is the embedded BreachHound application/window icon.
var appIcon fyne.Resource = fyne.NewStaticResource("breachhound.svg", iconSVG)
