package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"github.com/FlinnZee/breachhound/internal/core"
)

// breachTheme is BreachHound's dark, high-contrast palette. It embeds the
// default theme and overrides the colors that define the brand look.
type breachTheme struct{ fyne.Theme }

func newBreachTheme() breachTheme { return breachTheme{theme.DefaultTheme()} }

func (t breachTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return hex(0x0e1116)
	case theme.ColorNameForeground:
		return hex(0xe6edf3)
	case theme.ColorNamePrimary:
		return hex(0x2dd4bf) // teal accent
	case theme.ColorNameButton:
		return hex(0x1b2230)
	case theme.ColorNameHover:
		return hex(0x232c3d)
	case theme.ColorNameInputBackground:
		return hex(0x161b22)
	case theme.ColorNameOverlayBackground, theme.ColorNameMenuBackground:
		return hex(0x161b22)
	case theme.ColorNameSeparator:
		return hex(0x30363d)
	case theme.ColorNameDisabled:
		return hex(0x6e7681)
	case theme.ColorNamePlaceHolder:
		return hex(0x8b949e)
	case theme.ColorNameScrollBar:
		return hex(0x30363d)
	}
	// Fall back to the default theme's dark variant for anything not overridden.
	return t.Theme.Color(name, theme.VariantDark)
}

func (t breachTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 8
	}
	return t.Theme.Size(name)
}

// hex builds an opaque color from a 0xRRGGBB literal.
func hex(rgb uint32) color.NRGBA {
	return color.NRGBA{
		R: uint8(rgb >> 16),
		G: uint8(rgb >> 8),
		B: uint8(rgb),
		A: 0xff,
	}
}

// verdictColor is the banner background for each verdict.
func verdictColor(v core.Verdict) color.Color {
	switch v {
	case core.VerdictCompromised:
		return hex(0xb5271f)
	case core.VerdictReview:
		return hex(0xb07d12)
	default:
		return hex(0x1f7a44)
	}
}

// severityColor maps a finding severity to its chip color.
func severityColor(s core.Severity) color.Color {
	switch s {
	case core.SevCritical:
		return hex(0xf85149)
	case core.SevHigh:
		return hex(0xff8c42)
	case core.SevMedium:
		return hex(0xf2cc60)
	case core.SevLow:
		return hex(0x8b949e)
	default:
		return hex(0x6e7681)
	}
}
