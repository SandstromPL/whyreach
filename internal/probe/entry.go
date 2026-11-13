package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Budget is the longest the probe process may run. It stays under the probe
// container's 8 s limit (INITIAL.md §4.4) so the results get written; the
// executor passes a smaller one when the diagnosis has less time left.
const Budget = 6 * time.Second

// Exit codes of `whyreach __probe`: it fails only on an internal error.
const (
	ExitOK       = 0
	ExitInternal = 4
)

// Main is the entrypoint of the hidden `whyreach __probe --spec '<json>'`
// subcommand, which runs inside the probe container. It writes one JSON
// evidence record per line to stdout. Failed checks are evidence, not errors.
//
// budget bounds the whole batch; 0 or anything above Budget means Budget.
func Main(ctx context.Context, specJSON string, budget time.Duration, stdout, stderr io.Writer) int {
	specs, err := DecodeSpecs(specJSON)
	if err != nil {
		fmt.Fprintln(stderr, "whyreach __probe:", err)
		return ExitInternal
	}
	if budget <= 0 || budget > Budget {
		budget = Budget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	netns := SelfNetnsID()
	enc := json.NewEncoder(stdout)
	for _, ev := range Run(ctx, DefaultEnv(), specs) {
		ev.Context.NetnsID = netns
		if err := enc.Encode(ev); err != nil {
			fmt.Fprintln(stderr, "whyreach __probe: write result:", err)
			return ExitInternal
		}
	}
	return ExitOK
}

// DecodeSpecs parses and validates a batch of specs.
func DecodeSpecs(s string) ([]Spec, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.DisallowUnknownFields()
	var specs []Spec
	if err := dec.Decode(&specs); err != nil {
		return nil, fmt.Errorf("decode specs: %w", err)
	}
	if dec.More() {
		return nil, errors.New("decode specs: trailing data")
	}
	if len(specs) == 0 || len(specs) > MaxSpecs {
		return nil, fmt.Errorf("want 1 to %d specs, got %d", MaxSpecs, len(specs))
	}
	for i, sp := range specs {
		if err := sp.Validate(); err != nil {
			return nil, fmt.Errorf("spec %d: %w", i, err)
		}
	}
	return specs, nil
}

// EncodeSpecs is DecodeSpecs's inverse, for the executor.
func EncodeSpecs(specs []Spec) (string, error) {
	b, err := json.Marshal(specs)
	return string(b), err
}
