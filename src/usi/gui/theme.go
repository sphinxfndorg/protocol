// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/theme.go
package gui

import (
	"image/color"
	"math/big"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// =========================================================================
// COLOR PALETTE — consistent across all screens
// =========================================================================
var (
	colSurface   = color.RGBA{20, 23, 32, 255}
	colSurface2  = color.RGBA{26, 31, 46, 255}
	colAccent    = color.RGBA{74, 222, 158, 255}
	colAccentDim = color.RGBA{74, 222, 158, 30}
	colText      = color.RGBA{232, 236, 245, 255}
	colMuted     = color.RGBA{139, 147, 168, 255}
	colFaint     = color.RGBA{77, 85, 107, 255}
	colDanger    = color.RGBA{255, 107, 107, 255}
	colWarn      = color.RGBA{255, 179, 71, 255}
	colInfo      = color.RGBA{96, 165, 250, 255}
	colBorder    = color.RGBA{255, 255, 255, 18}
	colBorder2   = color.RGBA{255, 255, 255, 33}
)

// formatSPXAmount renders an SPX amount (already converted from nSPX) as a
// comma-grouped, human-readable string.
//
// Amounts here can run into the millions (genesis allocations, large
// balances) while retaining up to 18 decimal places of nSPX precision, so a
// plain Text('f', 6) reads as an ungrouped wall of digits like
// "30000000.000000" — technically correct but not what anyone actually
// wants to see. This groups the integer part with commas every 3 digits
// and drops the decimal part entirely when it's all zeros (the common
// case for round genesis/reward amounts), trimming trailing zeros
// otherwise so "1.500000" becomes "1.5" rather than carrying six digits of
// padding.
func formatSPXAmount(amount *big.Float) string {
	raw := amount.Text('f', 6)

	neg := strings.HasPrefix(raw, "-")
	if neg {
		raw = raw[1:]
	}

	intPart, decPart := raw, ""
	if dot := strings.IndexByte(raw, '.'); dot != -1 {
		intPart, decPart = raw[:dot], raw[dot+1:]
	}
	decPart = strings.TrimRight(decPart, "0")

	var grouped strings.Builder
	for i, d := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(d)
	}

	result := grouped.String()
	if decPart != "" {
		result += "." + decPart
	}
	if neg {
		result = "-" + result
	}
	return result
}

// =========================================================================
// UI HELPER COMPONENTS
// =========================================================================

// styledCard returns a rounded surface container wrapping content.
func styledCard(content fyne.CanvasObject, minW, minH float32) fyne.CanvasObject {
	bg := canvas.NewRectangle(colSurface)
	bg.CornerRadius = 12
	bg.StrokeColor = colBorder
	bg.StrokeWidth = 1
	bg.SetMinSize(fyne.NewSize(minW, minH))
	return container.NewMax(bg, container.NewPadded(content))
}

// sectionLabel returns a small caps-style muted label for section titles.
func sectionLabel(text string) fyne.CanvasObject {
	t := canvas.NewText(strings.ToUpper(text), colFaint)
	t.TextSize = 10
	t.TextStyle = fyne.TextStyle{Monospace: true}
	return t
}

// screenTitle returns the large bold title used at the top of each screen.
func screenTitle(text string) fyne.CanvasObject {
	t := canvas.NewText(text, colAccent)
	t.TextSize = 22
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

// screenSubtitle returns the muted description under a screen title.
func screenSubtitle(text string) fyne.CanvasObject {
	t := canvas.NewText(text, colMuted)
	t.TextSize = 13
	return t
}

// hRule is a thin horizontal divider.
func hRule() fyne.CanvasObject {
	r := canvas.NewRectangle(colBorder)
	r.SetMinSize(fyne.NewSize(0, 1))
	return r
}

// spacer creates a vertical blank space of height h.
func spacer(h float32) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.SetMinSize(fyne.NewSize(0, h))
	return r
}

// infoRow renders a label + value pair for info panels.
func infoRow(label, value string, valueColor color.Color) fyne.CanvasObject {
	lbl := canvas.NewText(label, colMuted)
	lbl.TextSize = 11
	val := canvas.NewText(value, valueColor)
	val.TextSize = 11
	val.TextStyle = fyne.TextStyle{Monospace: true}
	return container.NewHBox(lbl, layout.NewSpacer(), val)
}

// infoPanel renders a card with a title and a list of label/value rows.
func infoPanel(title string, rows []fyne.CanvasObject) fyne.CanvasObject {
	inner := container.NewVBox()
	inner.Add(sectionLabel(title))
	inner.Add(spacer(10))
	for i, row := range rows {
		inner.Add(row)
		if i < len(rows)-1 {
			inner.Add(spacer(6))
		}
	}
	return styledCard(inner, 240, 0)
}

// alertBox renders a colored notice box.
func alertBox(text string, bg, fg color.RGBA) fyne.CanvasObject {
	t := widget.NewLabel(text)
	t.Wrapping = fyne.TextWrapWord
	t.TextStyle = fyne.TextStyle{Italic: true}
	bgRect := canvas.NewRectangle(bg)
	bgRect.CornerRadius = 8
	bgRect.StrokeColor = fg
	bgRect.StrokeWidth = 1
	return container.NewMax(bgRect, container.NewPadded(t))
}

// opLayout builds the standard two-column layout for operation screens:
// left column = form, right column = info panel (fixed ~260px).
func opLayout(form, panel fyne.CanvasObject) fyne.CanvasObject {
	split := container.NewHSplit(
		container.NewPadded(form),
		container.NewPadded(panel),
	)
	split.Offset = 0.62
	return split
}
