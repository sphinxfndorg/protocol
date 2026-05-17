// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/gui/utils/widgets.go
package utils

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// SizedLabel is a custom label that allows text size control through scaling
type SizedLabel struct {
	widget.Label
	scale float32
}

// NewSizedLabel creates a new label with size scaling
func NewSizedLabel(text string, scale float32) *SizedLabel {
	label := &SizedLabel{
		scale: scale,
	}
	label.ExtendBaseWidget(label)
	label.SetText(text)
	return label
}

// MinSize returns the minimum size with scaling applied
func (l *SizedLabel) MinSize() fyne.Size {
	min := l.Label.MinSize()
	return fyne.NewSize(min.Width*l.scale, min.Height*l.scale)
}

// CreateLargeHeader creates a large header with custom sizing
func CreateLargeHeader(title, subtitle string) fyne.CanvasObject {
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subtitleLabel := widget.NewLabelWithStyle(subtitle, fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	// Use padding to create the appearance of larger text
	return container.NewVBox(
		container.NewPadded(titleLabel),
		subtitleLabel,
	)
}
