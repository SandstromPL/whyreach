package evidence

import (
	"cmp"
	"fmt"
	"slices"
	"sync"
)

// Store collects evidence during one diagnosis. Collectors add records
// concurrently; Finalize numbers them in a canonical order, so the same
// evidence always gets the same IDs regardless of which goroutine finished
// first.
type Store struct {
	mu    sync.Mutex
	items []Evidence
}

// Add records evidence. IDs are assigned later by Finalize.
func (s *Store) Add(e ...Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, e...)
}

// Len is the number of records so far.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Snapshot returns the records collected so far, in canonical order, without
// IDs. The engine uses it to decide what to collect next.
func (s *Store) Snapshot() []Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.items)
	sortCanonical(out)
	return out
}

// Finalize sorts the records canonically, assigns IDs ev-01, ev-02, … and
// returns them.
func (s *Store) Finalize() []Evidence {
	out := s.Snapshot()
	for i := range out {
		out[i].ID = fmt.Sprintf("ev-%02d", i+1)
	}
	return out
}

func sortCanonical(items []Evidence) {
	slices.SortStableFunc(items, func(a, b Evidence) int {
		return cmp.Or(
			cmp.Compare(kindRank(a.Kind), kindRank(b.Kind)),
			cmp.Compare(contextRank(a.Context), contextRank(b.Context)),
			cmp.Compare(a.Context.Name, b.Context.Name),
			cmp.Compare(a.Context.Container, b.Context.Container),
			cmp.Compare(a.Subject, b.Subject),
			cmp.Compare(payloadKey(a), payloadKey(b)),
			cmp.Compare(a.Status, b.Status),
		)
	})
}

func kindRank(k Kind) int {
	if r, ok := kindOrder[k]; ok {
		return r
	}
	return len(kindOrder)
}

func contextRank(c ContextRef) int {
	if c.Kind == ContextHost {
		return 0
	}
	return 1
}

// payloadKey orders records that share kind, context and subject.
func payloadKey(e Evidence) string {
	switch d := e.Data.(type) {
	case TCPProbe:
		return d.Via + " " + d.Addr.String()
	case DNSProbe:
		return d.Name
	case Container:
		return d.ID
	default:
		return ""
	}
}
