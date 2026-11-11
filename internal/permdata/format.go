// Package permdata holds the requirements of every terraform-provider-aws
// resource type, generated from the provider source and embedded in the
// binary. A default run reads them from here, so it needs no clone of the
// provider and no parse of its Go source.
//
// The table merges the requirements of one provider version per major
// version (see formatVersion). The generate-permissions command writes it
// with Generate. Decode reads it back, and Provider serves one version's
// requirements as an iam.Resolver.
package permdata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/elecnix/terraform-permcheck/internal/iam"
	"github.com/elecnix/terraform-permcheck/internal/providerversion"
)

// formatVersion is the version of the table format. Bump it when the format
// changes in a way an older reader would misread, and regenerate the table.
//
// Format 2 merges the tables of several provider versions, one per major
// version, into one file:
//
//	{
//	  "format": 2,
//	  "provider": "hashicorp/terraform-provider-aws",
//	  "refs": {"5": "v5.100.0", "6": "v6.72.0"},
//	  "resources": {
//	    "aws_widget": {
//	      "incomplete": [{"op":"delete","providers":["6"]}],
//	      "op_providers": {"list": ["6"]},
//	      "ops": {
//	        "create": [
//	          {"action":"demo:CreateWidget"},
//	          {"action":"demo:TagResource","attribute":"tags","providers":["6"]}
//	        ],
//	        "list": [
//	          {"action":"demo:ListWidgets"}
//	        ]
//	      }
//	    },
//	    "aws_gadget": {
//	      "providers": ["5"],
//	      "ops": {...}
//	    }
//	  }
//	}
//
// refs maps each major version to the provider ref its requirements come
// from. Anything every version has is written once, as format 1 wrote it.
// Anything only some versions have carries "providers", the major versions
// it applies to:
//
//   - on a resource type, the versions that have the type;
//   - in "op_providers", the versions that have the operation, when not
//     every version that has the type does;
//   - on a requirement, the versions whose operation reaches the action on
//     that path, when not every version that has the operation does;
//   - on an "incomplete" entry, the versions whose parse of the operation
//     missed calls, when not every version that has the type did.
//
// A missing "providers" means every version that has the enclosing type or
// operation. An operation's requirements keep each version's order: the
// list is the shortest merge of the versions' lists that keeps the order of
// every one of them, so a version's view reads its requirements in the order
// its parse emitted them.
const formatVersion = 2

// providerName names the source the table is generated from.
const providerName = "hashicorp/terraform-provider-aws"

// Version is the requirements of one provider version, as its parse found
// them: an input of Generate.
type Version struct {
	// Ref is the provider ref, such as "v5.100.0".
	Ref string
	// Schemas maps each terraform resource type to its schema.
	Schemas map[string]*iam.Schema
}

// Table is a decoded permissions table.
type Table struct {
	// Refs lists the provider refs the table was generated from, one per
	// major version, oldest first.
	Refs []string
	// Schemas maps each ref of Refs to the schema of each resource type
	// that version has.
	Schemas map[string]map[string]*iam.Schema
}

// RefFor returns the ref the table holds for major version major.
func (t *Table) RefFor(major int) (string, bool) {
	for _, ref := range t.Refs {
		if m, _ := providerversion.Major(ref); m == major {
			return ref, true
		}
	}
	return "", false
}

// Newest returns the ref of the newest provider version in the table.
func (t *Table) Newest() string {
	return t.Refs[len(t.Refs)-1]
}

// file is the JSON shape of a table.
type file struct {
	Format    int                 `json:"format"`
	Provider  string              `json:"provider"`
	Refs      map[string]string   `json:"refs"`
	Resources map[string]resource `json:"resources"`
}

// resource is the JSON shape of one resource type's schemas.
type resource struct {
	Providers   []string                 `json:"providers,omitempty"`
	Incomplete  []incompleteOp           `json:"incomplete,omitempty"`
	OpProviders map[string][]string      `json:"op_providers,omitempty"`
	Ops         map[string][]requirement `json:"ops"`
}

// incompleteOp is the JSON shape of an operation whose parse missed calls.
type incompleteOp struct {
	Op        string   `json:"op"`
	Providers []string `json:"providers,omitempty"`
}

// requirement is the JSON shape of an iam.Requirement. Zero gate fields are
// left out, so an ungated requirement every version has is just its action.
type requirement struct {
	Action       string   `json:"action"`
	Attribute    string   `json:"attribute,omitempty"`
	ValueGuarded bool     `json:"value_guarded,omitempty"`
	Changed      string   `json:"changed,omitempty"`
	BestEffort   bool     `json:"best_effort,omitempty"`
	Providers    []string `json:"providers,omitempty"`
}

// majorSet is a set of the versions being merged, by index into the
// versions sorted oldest first.
type majorSet []bool

// subset returns the providers of s, or nil when s holds every version of
// parent, so that the JSON leaves it out.
func (s majorSet) subset(parent majorSet, majors []string) []string {
	same := true
	var out []string
	for i, in := range s {
		if in {
			out = append(out, majors[i])
		}
		if in != parent[i] {
			same = false
		}
	}
	if same {
		return nil
	}
	return out
}

// mergedRequirement is a requirement and the versions that have it.
type mergedRequirement struct {
	iam.Requirement
	in majorSet
}

// Generate merges the schemas of each provider version into one table. Each
// version must have a different major version. The output is deterministic:
// types, operations and incomplete operations are sorted, and requirements
// keep the order the parser emitted them in (see formatVersion). Each
// requirement sits on its own line, so a regenerated table diffs line by
// line.
func Generate(versions []Version) ([]byte, error) {
	if len(versions) == 0 {
		return nil, fmt.Errorf("generate permissions table: no provider versions")
	}
	versions, majors, err := sortVersions(versions)
	if err != nil {
		return nil, err
	}
	n := len(versions)

	var b bytes.Buffer
	fmt.Fprintf(&b, "{\n  \"format\": %d,\n  \"provider\": %s,\n  \"refs\": {", formatVersion, quote(providerName))
	for i, v := range versions {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\n    %s: %s", quote(majors[i]), quote(v.Ref))
	}
	b.WriteString("\n  },\n  \"resources\": {")

	all := make(majorSet, n)
	for i := range all {
		all[i] = true
	}
	types := map[string]bool{}
	for _, v := range versions {
		for tfType := range v.Schemas {
			types[tfType] = true
		}
	}
	for i, tfType := range sortedKeys(types) {
		// has is the versions that have the type, and schemas their
		// schemas, nil for the others.
		has := make(majorSet, n)
		schemas := make([]*iam.Schema, n)
		ops := map[string]bool{}
		incompleteOps := map[string]bool{}
		for j, v := range versions {
			s, ok := v.Schemas[tfType]
			if !ok {
				continue
			}
			has[j], schemas[j] = true, s
			for op := range s.Ops {
				ops[op] = true
			}
			for _, op := range incomplete(s.Incomplete) {
				incompleteOps[op] = true
			}
		}

		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\n    %s: {", quote(tfType))
		if p := has.subset(all, majors); p != nil {
			if err := writeField(&b, "providers", p); err != nil {
				return nil, err
			}
		}
		if len(incompleteOps) > 0 {
			var entries []incompleteOp
			for _, op := range sortedKeys(incompleteOps) {
				in := make(majorSet, n)
				for j, s := range schemas {
					in[j] = s != nil && s.Incomplete[op]
				}
				entries = append(entries, incompleteOp{Op: op, Providers: in.subset(has, majors)})
			}
			if err := writeField(&b, "incomplete", entries); err != nil {
				return nil, err
			}
		}
		opIn := make(map[string]majorSet, len(ops))
		opProviders := map[string][]string{}
		for op := range ops {
			in := make(majorSet, n)
			for j, s := range schemas {
				if s != nil {
					_, in[j] = s.Ops[op]
				}
			}
			opIn[op] = in
			if p := in.subset(has, majors); p != nil {
				opProviders[op] = p
			}
		}
		if len(opProviders) > 0 {
			if err := writeField(&b, "op_providers", opProviders); err != nil {
				return nil, err
			}
		}

		b.WriteString("\n      \"ops\": {")
		for j, op := range sortedKeys(ops) {
			if j > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, "\n        %s: [", quote(op))
			reqs := mergeOp(schemas, op)
			for k, r := range reqs {
				raw, err := json.Marshal(requirement{
					Action:       r.Action,
					Attribute:    r.Attribute,
					ValueGuarded: r.ValueGuarded,
					Changed:      r.Changed,
					BestEffort:   r.BestEffort,
					Providers:    r.in.subset(opIn[op], majors),
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

// writeField writes one field of a resource on its own line, followed by a
// comma: the ops field always comes after it.
func writeField(b *bytes.Buffer, name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Fprintf(b, "\n      %s: %s,", quote(name), raw)
	return nil
}

// sortVersions returns the versions oldest first, with the major version of
// each. Two versions of the same major are an error: the table holds one per
// major.
func sortVersions(versions []Version) ([]Version, []string, error) {
	type keyed struct {
		v     Version
		major int
	}
	ks := make([]keyed, len(versions))
	for i, v := range versions {
		m, ok := providerversion.Major(v.Ref)
		if !ok {
			return nil, nil, fmt.Errorf("generate permissions table: ref %q has no major version", v.Ref)
		}
		ks[i] = keyed{v, m}
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].major < ks[j].major })
	out := make([]Version, len(ks))
	majors := make([]string, len(ks))
	for i, k := range ks {
		if i > 0 && ks[i-1].major == k.major {
			return nil, nil, fmt.Errorf("generate permissions table: %s and %s have the same major version", ks[i-1].v.Ref, k.v.Ref)
		}
		out[i], majors[i] = k.v, strconv.Itoa(k.major)
	}
	return out, majors, nil
}

// mergeOp merges the requirements of op across the versions' schemas, nil
// for a version that lacks the type. A requirement two versions share comes
// out once. The result keeps the order of each version's list (see
// formatVersion).
func mergeOp(schemas []*iam.Schema, op string) []mergedRequirement {
	var out []mergedRequirement
	for j, s := range schemas {
		if s == nil {
			continue
		}
		out = mergeInto(out, s.Ops[op], j, len(schemas))
	}
	return out
}

// mergeInto merges version j's requirements into the merged list, matching
// the longest common subsequence: a matched requirement gains version j, and
// the others keep their place relative to the matched ones. Where both lists
// have unmatched requirements between two matches, the merged list's come
// first.
func mergeInto(merged []mergedRequirement, reqs []iam.Requirement, j, n int) []mergedRequirement {
	// lcs[a][c] is the length of the longest common subsequence of
	// merged[a:] and reqs[c:].
	lcs := make([][]int, len(merged)+1)
	for a := range lcs {
		lcs[a] = make([]int, len(reqs)+1)
	}
	for a := len(merged) - 1; a >= 0; a-- {
		for c := len(reqs) - 1; c >= 0; c-- {
			if merged[a].Requirement == reqs[c] {
				lcs[a][c] = lcs[a+1][c+1] + 1
			} else {
				lcs[a][c] = max(lcs[a+1][c], lcs[a][c+1])
			}
		}
	}
	added := func(r iam.Requirement) mergedRequirement {
		in := make(majorSet, n)
		in[j] = true
		return mergedRequirement{Requirement: r, in: in}
	}
	out := make([]mergedRequirement, 0, len(merged)+len(reqs))
	a, c := 0, 0
	for a < len(merged) && c < len(reqs) {
		switch {
		case merged[a].Requirement == reqs[c] && lcs[a][c] == lcs[a+1][c+1]+1:
			m := merged[a]
			m.in = append(majorSet(nil), m.in...)
			m.in[j] = true
			out = append(out, m)
			a, c = a+1, c+1
		case lcs[a+1][c] >= lcs[a][c+1]:
			out = append(out, merged[a])
			a++
		default:
			out = append(out, added(reqs[c]))
			c++
		}
	}
	out = append(out, merged[a:]...)
	for ; c < len(reqs); c++ {
		out = append(out, added(reqs[c]))
	}
	return out
}

// Decode reads a table that Generate wrote. It refuses a table of another
// format version, and one whose providers name a major version its refs
// lack.
func Decode(data []byte) (*Table, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decode permissions table: %w", err)
	}
	if f.Format != formatVersion {
		return nil, fmt.Errorf("permissions table has format %d, this build reads format %d", f.Format, formatVersion)
	}
	if len(f.Refs) == 0 {
		return nil, fmt.Errorf("decode permissions table: no refs")
	}
	majors := make([]int, 0, len(f.Refs))
	for key, ref := range f.Refs {
		m, ok := providerversion.Major(key)
		if !ok || strconv.Itoa(m) != key {
			return nil, fmt.Errorf("decode permissions table: refs key %q is not a major version", key)
		}
		if rm, ok := providerversion.Major(ref); !ok || rm != m {
			return nil, fmt.Errorf("decode permissions table: ref %q is not of major version %s", ref, key)
		}
		majors = append(majors, m)
	}
	sort.Ints(majors)

	tbl := &Table{Schemas: make(map[string]map[string]*iam.Schema, len(majors))}
	for _, m := range majors {
		ref := f.Refs[strconv.Itoa(m)]
		tbl.Refs = append(tbl.Refs, ref)
		tbl.Schemas[ref] = make(map[string]*iam.Schema, len(f.Resources))
	}
	// in returns whether major is among providers. The caller has checked
	// that major has the enclosing type or operation, so no providers means
	// it does. It fails on a major the refs lack.
	in := func(providers []string, major string) (bool, error) {
		if len(providers) == 0 {
			return true, nil
		}
		found := false
		for _, p := range providers {
			if _, ok := f.Refs[p]; !ok {
				return false, fmt.Errorf("decode permissions table: providers names %q, the table's refs are %v", p, f.Refs)
			}
			found = found || p == major
		}
		return found, nil
	}

	for tfType, r := range f.Resources {
		for _, m := range majors {
			major := strconv.Itoa(m)
			ok, err := in(r.Providers, major)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", tfType, err)
			}
			if !ok {
				continue
			}
			s := &iam.Schema{TypeName: tfType, Ops: make(map[string][]iam.Requirement, len(r.Ops))}
			for op, reqs := range r.Ops {
				hasOp, err := in(r.OpProviders[op], major)
				if err != nil {
					return nil, fmt.Errorf("%s %s: %w", tfType, op, err)
				}
				if !hasOp {
					continue
				}
				out := make([]iam.Requirement, 0, len(reqs))
				for _, q := range reqs {
					keep, err := in(q.Providers, major)
					if err != nil {
						return nil, fmt.Errorf("%s %s %s: %w", tfType, op, q.Action, err)
					}
					if !keep {
						continue
					}
					out = append(out, iam.Requirement{Action: q.Action, Gate: iam.Gate{
						Attribute:    q.Attribute,
						ValueGuarded: q.ValueGuarded,
						Changed:      q.Changed,
						BestEffort:   q.BestEffort,
					}})
				}
				s.Ops[op] = out
			}
			for _, inc := range r.Incomplete {
				keep, err := in(inc.Providers, major)
				if err != nil {
					return nil, fmt.Errorf("%s incomplete %s: %w", tfType, inc.Op, err)
				}
				if !keep {
					continue
				}
				if s.Incomplete == nil {
					s.Incomplete = make(map[string]bool, len(r.Incomplete))
				}
				s.Incomplete[inc.Op] = true
			}
			tbl.Schemas[f.Refs[major]][tfType] = s
		}
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
