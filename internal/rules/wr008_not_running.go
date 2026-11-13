package rules

import (
	"fmt"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// WR008: the destination is not running, is restarting, or is unhealthy.
// It is checked before any probe: a restarting container has no address and
// its network namespace can't be joined (rule experiments, E4).
type wr008 struct{}

func (wr008) ID() string                { return "WR008" }
func (wr008) Layer() Layer              { return LayerDestination }
func (wr008) Requires() []evidence.Kind { return []evidence.Kind{evidence.KindContainer} }
func (wr008) Supersedes() []string      { return []string{"WR001", "WR005", "WR016"} }

// A container that restarted this often and started this recently is
// crash-looping even if it happens to be running at the moment of inspection.
const (
	crashLoopRestarts = 3
	crashLoopUptime   = 30 * time.Second
)

func (r wr008) Evaluate(v evidence.View) []Finding {
	matches := v.Destinations().All()
	if len(matches) == 0 {
		return nil
	}
	var down []evidence.Match
	for _, m := range matches {
		if healthy(m.C, observedAt(v, m.ID)) {
			return nil // a replica is up: connections can be served
		}
		down = append(down, m)
	}
	m := down[0]
	c := m.C
	name := containerLabel(c)
	f := Finding{
		RuleID: r.ID(), Layer: r.Layer(), DocURL: DocURL(r.ID()),
		Supporting: ids(m.ID),
	}
	switch c.State {
	case evidence.StateRestarting:
		f.Confidence = High
		f.Title = fmt.Sprintf("%s is restarting", c.DisplayName())
		f.Explanation = fmt.Sprintf("%s is restarting (%d %s so far, last exit code %d). A restarting container has no network address, so nothing can connect to it.",
			name, c.RestartCount, plural(c.RestartCount, "restart", "restarts"), c.ExitCode)
		f.Fix = fmt.Sprintf("Find out why it keeps exiting (docker logs %s) and fix that; the connection will work once it stays up.", c.Name)
	case evidence.StatePaused:
		f.Confidence = High
		f.Title = fmt.Sprintf("%s is paused", c.DisplayName())
		f.Explanation = fmt.Sprintf("%s is paused: its processes are frozen and can't accept connections.", name)
		f.Fix = fmt.Sprintf("Unpause it: docker unpause %s.", c.Name)
	case evidence.StateRunning:
		f.Confidence = Medium
		if c.Health == "unhealthy" {
			f.Title = fmt.Sprintf("%s is running but unhealthy", c.DisplayName())
			f.Explanation = fmt.Sprintf("%s is running, but its healthcheck fails, so it may not be serving yet or at all.", name)
		} else {
			f.Title = fmt.Sprintf("%s keeps restarting", c.DisplayName())
			f.Explanation = fmt.Sprintf("%s has restarted %d times and started only moments before this check: it is probably crash-looping and has no address between restarts.", name, c.RestartCount)
		}
		f.Fix = fmt.Sprintf("Check its logs (docker logs %s) and healthcheck, and fix what makes it fail.", c.Name)
	default: // exited, created, dead, removing
		f.Confidence = High
		f.Title = fmt.Sprintf("%s is not running", c.DisplayName())
		state := "is " + c.State
		if c.State == evidence.StateExited {
			state = fmt.Sprintf("has exited with code %d", c.ExitCode)
		}
		f.Explanation = fmt.Sprintf("%s %s and has no network address, so nothing can connect to it.", name, state)
		f.Fix = fmt.Sprintf("Start it (with Compose: docker compose up -d %s) and check why it stopped: docker logs %s.", c.DisplayName(), c.Name)
	}
	if len(down) > 1 {
		f.Explanation += fmt.Sprintf(" None of the %d containers that answer to %s is up.", len(down), v.Question().To.Host)
		for _, d := range down[1:] {
			f.Supporting = ids(append(f.Supporting, d.ID)...)
		}
	}
	return []Finding{f}
}

// healthy reports a container that can serve connections as far as its
// state shows.
func healthy(c evidence.Container, observed time.Time) bool {
	if !c.Running() || c.Health == "unhealthy" {
		return false
	}
	return !crashLooping(c, observed)
}

func crashLooping(c evidence.Container, observed time.Time) bool {
	if c.RestartCount < crashLoopRestarts || c.StartedAt.IsZero() || observed.IsZero() {
		return false
	}
	return observed.Sub(c.StartedAt) < crashLoopUptime
}

// observedAt is when the record with id was observed.
func observedAt(v evidence.View, id string) time.Time {
	e, ok := v.Get(id)
	if !ok {
		return time.Time{}
	}
	return e.ObservedAt
}
