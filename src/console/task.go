// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/task.go
package logger

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// StatusLine renders a compact, always-current dashboard panel of key/value
// fields (network status, height vs. tip, download rate, ETA, validator
// counts, mempool size, ...) as part of the live region. Unlike Spinner and
// ProgressBar it never "finishes" -- it simply reflects whatever fields
// were last set.
//
// Rendered as one aligned "label   value" line per field, under an optional
// title line, e.g.:
//
//	SPHINX Node
//	Network      ONLINE
//	Peers        8
//	Height       184,291 / 200,000
//	Sync         [████████████████░░░░] 92.1%
//	Behind       15,709 blocks
//	Rate         842 blocks/s
//	ETA          00:00:19
//	Consensus    PAUSED — synchronizing
type StatusLine struct {
	mu     sync.Mutex
	title  string
	order  []string
	fields map[string]string
}

// statusLabelWidth is the column width labels are padded to before the
// value, so every field lines up in a neat left-aligned column.
const statusLabelWidth = 13

// NewStatusLine creates an empty status line.
func NewStatusLine() *StatusLine {
	return &StatusLine{fields: make(map[string]string)}
}

// SetTitle sets an optional header line rendered above the fields (e.g.
// "SPHINX Node"). Pass an empty string to omit the header.
func (sl *StatusLine) SetTitle(title string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.title = title
}

// Set adds or updates a field. First-set order is preserved on redraw.
func (sl *StatusLine) Set(key, value string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if _, exists := sl.fields[key]; !exists {
		sl.order = append(sl.order, key)
	}
	sl.fields[key] = value
}

// Clear removes a field entirely.
func (sl *StatusLine) Clear(key string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if _, exists := sl.fields[key]; !exists {
		return
	}
	delete(sl.fields, key)
	for i, k := range sl.order {
		if k == key {
			sl.order = append(sl.order[:i], sl.order[i+1:]...)
			break
		}
	}
}

// Lines implements Renderable. Each field renders on its own line as
// "label   value", left-padded to statusLabelWidth so the values form a
// clean column -- this is what makes the dashboard look like:
//
//	SPHINX Node
//	Network      ONLINE
//	Peers        8
//	...
//
// rather than one long horizontal line of "key: value   key: value" pairs.
func (sl *StatusLine) Lines() []string {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if len(sl.order) == 0 {
		return nil
	}
	lines := make([]string, 0, len(sl.order)+1)
	if sl.title != "" {
		lines = append(lines, fmt.Sprintf("%s%s%s", FGCyan, sl.title, ResetColor))
	}
	for _, k := range sl.order {
		label := k
		if pad := statusLabelWidth - len(label); pad > 0 {
			label += strings.Repeat(" ", pad)
		}
		lines = append(lines, fmt.Sprintf("%s%s%s%s", ColorMuted, label, ResetColor, sl.fields[k]))
	}
	return lines
}

// TaskStatus is the state of one node in a Task tree.
type TaskStatus int

const (
	TaskPending TaskStatus = iota
	TaskRunning
	TaskSuccess
	TaskWarning
	TaskError
	TaskSkipped
)

func (s TaskStatus) label() (text, color string) {
	switch s {
	case TaskPending:
		return "PENDING", ColorMuted
	case TaskRunning:
		return "RUNNING", FGBlue
	case TaskSuccess:
		return "DONE", FGGreen
	case TaskWarning:
		return "WARN", FGYellow
	case TaskError:
		return "FAIL", FGRed
	case TaskSkipped:
		return "SKIP", ColorMuted
	default:
		return "?", ColorMuted
	}
}

// Task is one node in a hierarchical progress tree, e.g. node startup with
// genesis / peer-discovery / consensus-startup as children. A root Task
// implements Renderable directly -- attach it to a Renderer and the whole
// tree renders and animates as a single live block.
type Task struct {
	mu       sync.Mutex
	name     string
	status   TaskStatus
	frameIdx int
	current  int64
	total    int64
	hasBar   bool
	children []*Task
	start    time.Time
	end      time.Time
}

// NewTask creates a task node in the pending state.
func NewTask(name string) *Task {
	return &Task{name: name, status: TaskPending}
}

// AddChild attaches a child node and returns the parent for chaining.
func (t *Task) AddChild(c *Task) *Task {
	t.mu.Lock()
	t.children = append(t.children, c)
	t.mu.Unlock()
	return t
}

// SetStatus transitions the task. Moving into TaskRunning starts the clock
// (if not already started); moving into any terminal status stops it.
func (t *Task) SetStatus(s TaskStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status = s
	if s == TaskRunning && t.start.IsZero() {
		t.start = time.Now()
	}
	if s >= TaskSuccess && t.end.IsZero() {
		t.end = time.Now()
	}
}

// SetProgress attaches a determinate current/total to the task, rendered
// as a mini progress bar beneath its line while it is running.
func (t *Task) SetProgress(current, total int64) {
	t.mu.Lock()
	t.current, t.total, t.hasBar = current, total, true
	t.mu.Unlock()
}

// Elapsed returns time spent running so far (or the final duration once
// the task reached a terminal status).
func (t *Task) Elapsed() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.elapsedLocked()
}

func (t *Task) elapsedLocked() time.Duration {
	switch {
	case !t.end.IsZero():
		return t.end.Sub(t.start)
	case !t.start.IsZero():
		return time.Since(t.start)
	default:
		return 0
	}
}

// Lines implements Renderable for the whole subtree rooted at t.
func (t *Task) Lines() []string {
	return t.render(0)
}

func (t *Task) render(depth int) []string {
	t.mu.Lock()
	if t.status == TaskRunning {
		t.frameIdx = (t.frameIdx + 1) % len(spinnerFrames)
	}
	name, status := t.name, t.status
	current, total, hasBar := t.current, t.total, t.hasBar
	elapsed := t.elapsedLocked()
	frame := spinnerFrames[t.frameIdx]
	children := append([]*Task{}, t.children...)
	t.mu.Unlock()

	indent := strings.Repeat("  ", depth)
	label, color := status.label()
	icon := stoppedSymbol
	switch status {
	case TaskRunning:
		icon = frame
	case TaskSuccess:
		icon = successSymbol
	case TaskWarning:
		icon = warningSymbol
	case TaskError:
		icon = errorSymbol
	}

	line := fmt.Sprintf("%s%s%s%s %s%-32s%s %s%-7s%s %s(%s)%s",
		indent, FGBlue, icon, ResetColor,
		Bold, name, ResetColor,
		color, label, ResetColor,
		ColorMuted, formatDuration(elapsed), ResetColor)

	out := []string{line}
	if hasBar && status == TaskRunning && total > 0 {
		var percent float64
		if total > 0 {
			percent = float64(current) / float64(total)
		}
		barWidth := 24
		filled := int(float64(barWidth) * percent)
		bar := fmt.Sprintf("%s%s%s%s%s",
			FGBlue, strings.Repeat("█", filled), ColorMuted, strings.Repeat("░", barWidth-filled), ResetColor)
		out = append(out, fmt.Sprintf("%s  %s %s%3.0f%%%s %s/%s",
			indent, bar, FGCyan, percent*100, ResetColor, formatNumber(current), formatNumber(total)))
	}

	for _, c := range children {
		out = append(out, c.render(depth+1)...)
	}
	return out
}
