// Package permdata holds the requirements of every terraform-provider-aws
// resource type, generated from the provider source and embedded in the
// binary. A default run reads them from here, so it needs no clone of the
// provider and no parse of its Go source.
//
// The generate-permissions command writes the table with Generate. Decode
// reads it back, and Provider serves it as an iam.Resolver.
package permdata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// formatVersion is the version of the table format. Bump it when the format
// changes in a way an older reader would misread, and regenerate the table.
const formatVersion = 1

// providerName names the source the table is generated from.
const providerName = "hashicorp/terraform-provider-aws"

// Table is a decoded permissions table.
type Table struct {
	// Ref is the provider ref the table was generated from, e.g. "v5.90.0".
	Ref string
	// Schemas maps each terraform resource type to its schema.
	Schemas map[string]*iam.Schema
}

// file is the JSON shape of a table.
type file struct {
	Format    int                 `json:"format"`
	Provider  string              `json:"provider"`
	Ref       string              `json:"ref"`
	Resources map[string]resource `json:"resources"`
}

// resource is the JSON shape of one resource type's schema. Incomplete lists
// the operations whose parse missed calls, sorted.
type resource struct {
	Incomplete []string                 `json:"incomplete,omitempty"`
	Ops        map[string][]requirement `json:"ops"`
}

// requirement is the JSON shape of an iam.Requirement. Zero gate fields are
// left out, so an ungated requirement is just its action.
type requirement struct {
	Action       string `json:"action"`
	Attribute    string `json:"attribute,omitempty"`
	ValueGuarded bool   `json:"value_guarded,omitempty"`
	Changed      string `json:"changed,omitempty"`
	BestEffort   bool   `json:"best_effort,omitempty"`
}

// Generate encodes the schema of each resource type as a table for the
// provider ref. The output is deterministic: types, operations and
// incomplete operations are sorted, and requirements keep the order the
// parser emitted them in. Each requirement sits on its own line, so a
// regenerated table diffs line by line.
func Generate(schemas map[string]*iam.Schema, ref string) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "{\n  \"format\": %d,\n  \"provider\": %s,\n  \"ref\": %s,\n  \"resources\": {", formatVersion, quote(providerName), quote(ref))
	for i, tfType := range sortedKeys(schemas) {
		s := schemas[tfType]
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\n    %s: {", quote(tfType))
		if inc := incomplete(s.Incomplete); len(inc) > 0 {
			raw, err := json.Marshal(inc)
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(&b, "\n      \"incomplete\": %s,", raw)
		}
		b.WriteString("\n      \"ops\": {")
		for j, op := range sortedKeys(s.Ops) {
			if j > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "\n        %s: [", quote(op))
			reqs := s.Ops[op]
			for k, r := range reqs {
				raw, err := json.Marshal(requirement{
					Action:       r.Action,
					Attribute:    r.Attribute,
					ValueGuarded: r.ValueGuarded,
					Changed:      r.Changed,
					BestEffort:   r.BestEffort,
				})
				if err != nil {
					return nil, err
				}
				if k > 0 {
					b.WriteByte(',')
				}
				b.WriteString("\n          ")
				b.Write(raw)
			}
			if len(reqs) > 0 {
				b.WriteString("\n        ")
			}
			b.WriteByte(']')
		}
		b.WriteString("\n      }\n    }")
	}
	b.WriteString("\n  }\n}\n")
	return b.Bytes(), nil
}

// Decode reads a table that encode wrote. It refuses a table of another
// format version.
func Decode(data []byte) (*Table, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decode permissions table: %w", err)
	}
	if f.Format != formatVersion {
		return nil, fmt.Errorf("permissions table has format %d, this build reads format %d", f.Format, formatVersion)
	}
	tbl := &Table{Ref: f.Ref, Schemas: make(map[string]*iam.Schema, len(f.Resources))}
	for tfType, r := range f.Resources {
		s := &iam.Schema{TypeName: tfType, Ops: make(map[string][]iam.Requirement, len(r.Ops))}
		for op, reqs := range r.Ops {
			out := make([]iam.Requirement, len(reqs))
			for i, q := range reqs {
				out[i] = iam.Requirement{Action: q.Action, Gate: iam.Gate{
					Attribute:    q.Attribute,
					ValueGuarded: q.ValueGuarded,
					Changed:      q.Changed,
					BestEffort:   q.BestEffort,
				}}
			}
			s.Ops[op] = out
		}
		for _, op := range r.Incomplete {
			if s.Incomplete == nil {
				s.Incomplete = make(map[string]bool, len(r.Incomplete))
			}
			s.Incomplete[op] = true
		}
		tbl.Schemas[tfType] = s
	}
	return tbl, nil
}

// incomplete lists the operations marked incomplete, sorted.
func incomplete(m map[string]bool) []string {
	var out []string
	for op, v := range m {
		if v {
			out = append(out, op)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// quote returns s as a JSON string.
func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
