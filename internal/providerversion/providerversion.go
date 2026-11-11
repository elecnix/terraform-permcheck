// Package providerversion finds the version of the AWS provider a plan or a
// terraform root uses. The embedded permissions table holds the requirements
// of one provider version per major version, and the check reads the ones of
// the major version the plan was made with.
//
// The exact version comes from the root's dependency lock file,
// .terraform.lock.hcl. A plan JSON does not record the version terraform
// installed, only the version constraints of the configuration
// (configuration.provider_config.<key>.version_constraint). A constraint
// still decides the major version when it admits only one of the majors the
// table has, such as "~> 5.0".
package providerversion

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Source is the registry address of the AWS provider, as a lock file and a
// plan's provider_config name it.
const Source = "registry.terraform.io/hashicorp/aws"

// LockFile is the name of the dependency lock file in a terraform root.
const LockFile = ".terraform.lock.hcl"

// Major returns the major version of a version or ref such as "v5.100.0",
// "5.100.0", "6" or "v6". It reports false when v does not start with a
// number.
func Major(v string) (int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	head, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(head)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// lockProviderRE matches the opening line of the AWS provider's block in a
// lock file, and lockVersionRE its version line.
var (
	lockProviderRE = regexp.MustCompile(`^\s*provider\s+"` + regexp.QuoteMeta(Source) + `"\s*\{\s*$`)
	lockVersionRE  = regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"\s*$`)
)

// FromLockFile returns the AWS provider version that the lock file in the
// terraform root dir pins, such as "5.100.0". It reports false when dir has
// no lock file or the lock file has no AWS provider. A lock file that cannot
// be read is an error.
//
// terraform init writes the file in a fixed layout: one provider block per
// provider, with its version on a line of its own. The reader relies on that
// layout rather than parse HCL.
func FromLockFile(dir string) (string, bool, error) {
	path := filepath.Join(dir, LockFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	in := false
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case !in:
			in = lockProviderRE.MatchString(line)
		case strings.TrimSpace(line) == "}":
			// The block closed without a version line.
			return "", false, fmt.Errorf("%s: the %s block has no version", path, Source)
		default:
			if m := lockVersionRE.FindStringSubmatch(line); m != nil {
				return m[1], true, nil
			}
		}
	}
	return "", false, sc.Err()
}

// planConfig is the part of a plan JSON that names the provider constraints.
type planConfig struct {
	Configuration struct {
		ProviderConfig map[string]struct {
			Name              string `json:"name"`
			FullName          string `json:"full_name"`
			VersionConstraint string `json:"version_constraint"`
		} `json:"provider_config"`
	} `json:"configuration"`
}

// Constraints returns the version constraints a plan JSON gives the AWS
// provider, one per provider configuration that sets one, such as
// "~> 5.0". Terraform installs a version that meets all of them. A plan
// that does not parse has none.
func Constraints(planJSON []byte) []string {
	var p planConfig
	if err := json.Unmarshal(planJSON, &p); err != nil {
		return nil
	}
	var out []string
	for _, c := range p.Configuration.ProviderConfig {
		if c.FullName != Source && (c.FullName != "" || c.Name != "aws") {
			continue
		}
		if c.VersionConstraint != "" {
			out = append(out, c.VersionConstraint)
		}
	}
	return out
}

// version is a version number as a constraint writes it. A missing part is
// zero.
type version [3]int

func parseVersion(s string) (version, int, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	// A pre-release or build suffix does not move the version across a
	// major boundary, so it is dropped.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return version{}, 0, false
	}
	var v version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return version{}, 0, false
		}
		v[i] = n
	}
	return v, len(parts), true
}

func (v version) less(w version) bool {
	for i := range v {
		if v[i] != w[i] {
			return v[i] < w[i]
		}
	}
	return false
}

// span is the range of versions [lo, hi) that a set of constraints admits.
type span struct {
	lo, hi version
}

// narrow intersects s with the versions one constraint term admits. A strict
// lower bound (>) is read as >=: it excludes a single release, which never
// empties a span of whole releases, so the answer is the same.
func (s *span) narrow(op string, v version, parts int) {
	setLo := func(w version) {
		if s.lo.less(w) {
			s.lo = w
		}
	}
	setHi := func(w version) {
		if w.less(s.hi) {
			s.hi = w
		}
	}
	switch op {
	case "", "=":
		setLo(v)
		next := v
		next[2]++
		setHi(next)
	case ">=", ">":
		setLo(v)
	case "<":
		setHi(v)
	case "<=":
		next := v
		next[2]++
		setHi(next)
	case "~>":
		setLo(v)
		// ~> 5 and ~> 5.0 allow any 5.x, ~> 5.1.2 any 5.1.x from 5.1.2.
		var up version
		if parts == 3 {
			up = version{v[0], v[1] + 1, 0}
		} else {
			up = version{v[0] + 1, 0, 0}
		}
		setHi(up)
	}
}

// constraintTermRE matches one term of a constraint, such as ">= 5.0".
var constraintTermRE = regexp.MustCompile(`^\s*(=|!=|>=|<=|>|<|~>)?\s*v?([0-9][0-9A-Za-z.+-]*)\s*$`)

// Admits reports whether the constraints admit some release of major
// version major. A constraint it cannot read admits every major, so it never
// rules out the version terraform installed.
func Admits(constraints []string, major int) bool {
	s := span{lo: version{major, 0, 0}, hi: version{major + 1, 0, 0}}
	for _, c := range constraints {
		for _, term := range strings.Split(c, ",") {
			m := constraintTermRE.FindStringSubmatch(term)
			if m == nil {
				continue
			}
			// An exclusion removes one release, never a whole major.
			if m[1] == "!=" {
				continue
			}
			v, parts, ok := parseVersion(m[2])
			if !ok {
				continue
			}
			s.narrow(m[1], v, parts)
		}
	}
	return s.lo.less(s.hi)
}
