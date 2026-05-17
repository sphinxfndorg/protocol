// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/gui/utils/component.go
package utils

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// CreateHeader creates a standardized header component with better styling
func CreateHeader(title string, subtitle string) fyne.CanvasObject {
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subtitleLabel := widget.NewLabelWithStyle(subtitle, fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	return container.NewVBox(
		titleLabel,
		subtitleLabel,
	)
}

// CreateBalanceDisplay creates a balance display component with better styling
func CreateBalanceDisplay(balance string, currency string) fyne.CanvasObject {
	// For larger text, we'll use a custom approach with padding and layout
	balanceLabel := widget.NewLabelWithStyle(balance, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	// Create a container with padding to make it appear larger
	balanceContainer := container.NewPadded(
		container.NewCenter(balanceLabel),
	)

	currencyLabel := widget.NewLabelWithStyle(currency, fyne.TextAlignCenter, fyne.TextStyle{})

	return container.NewVBox(
		balanceContainer,
		container.NewCenter(currencyLabel),
	)
}

// CreateLargeText creates a label with larger appearance
func CreateLargeText(text string) *widget.Label {
	label := widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	return label
}

// CreateActionButton creates a styled action button
func CreateActionButton(text string, action func()) *widget.Button {
	button := widget.NewButton(text, action)
	button.Importance = widget.MediumImportance
	return button
}

// CreateFormSection creates a form section with title
func CreateFormSection(title string, items ...fyne.CanvasObject) fyne.CanvasObject {
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	content := container.NewVBox(items...)
	content = container.NewPadded(content)

	return container.NewVBox(
		titleLabel,
		content,
	)
}

// CreateStatusIndicator creates a status indicator component
func CreateStatusIndicator(status string, isActive bool) fyne.CanvasObject {
	var icon string
	if isActive {
		icon = "🟢"
	} else {
		icon = "🔴"
	}

	statusLabel := widget.NewLabel(status)
	iconLabel := widget.NewLabel(icon)

	return container.NewHBox(
		iconLabel,
		statusLabel,
	)
}

// CreateCard creates a styled card component
func CreateCard(title string, content fyne.CanvasObject) *widget.Card {
	return widget.NewCard(title, "", content)
}

// CreateSpacer creates a flexible spacer
func CreateSpacer() fyne.CanvasObject {
	return layout.NewSpacer()
}

// CreateSeparator creates a visual separator
func CreateSeparator() fyne.CanvasObject {
	return widget.NewSeparator()
}

// CreateProgressBar creates a progress bar with label
func CreateProgressBar(labelText string) *widget.ProgressBar {
	return widget.NewProgressBar()
}

// CreateToolbar creates a simple toolbar
func CreateToolbar(items ...fyne.CanvasObject) fyne.CanvasObject {
	return container.NewHBox(items...)
}

// CreateHoverButton creates a button with hover effects
func CreateHoverButton(text string, action func()) *widget.Button {
	button := widget.NewButton(text, action)
	button.Importance = widget.MediumImportance
	return button
}

// CreateProgressBarWithLabel creates a progress bar with label
func CreateProgressBarWithLabel(labelText string, current, max float64) fyne.CanvasObject {
	label := widget.NewLabel(labelText)
	progress := widget.NewProgressBar()
	progress.SetValue(current / max)

	percentage := widget.NewLabel(fmt.Sprintf("%.1f%%", (current/max)*100))

	return container.NewVBox(
		container.NewHBox(label, layout.NewSpacer(), percentage),
		progress,
	)
}

// CreateStyledLabel creates a label with custom styling
func CreateStyledLabel(text string, alignment fyne.TextAlign, style fyne.TextStyle) *widget.Label {
	return widget.NewLabelWithStyle(text, alignment, style)
}

// CreateHeading creates a heading label
func CreateHeading(text string) *widget.Label {
	return widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
}

// CreateSubHeading creates a subheading label
func CreateSubHeading(text string) *widget.Label {
	return widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
}
