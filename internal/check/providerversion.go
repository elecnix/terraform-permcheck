package check

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/permdata"
	"github.com/elecnix/terraform-permcheck/internal/providerversion"
)

// VersionHints is what a run knows about the AWS provider version the plan
// or the terraform root uses, most authoritative first.
type VersionHints struct {
	// Explicit is the version the user set, such as "5", "5.100.0" or
	// "v6.72.0", or "". ExplicitFrom names where it was set, for errors.
	Explicit, ExplicitFrom string
	// Locked is the version the root's .terraform.lock.hcl pins, or "".
	Locked string
	// Constraints are the plan's version constraints for the provider.
	Constraints []string
	// Root is the --terraform-root directory, or "". Static is true in
	// static HCL mode, which reads no plan. Both shape the notice.
	Root   string
	Static bool
}

// unknown says why the hints name no version, for the notice.
func (h VersionHints) unknown() string {
	lock := providerversion.LockFile
	switch {
	case h.Static:
		return fmt.Sprintf("%s has no %s", h.Root, lock)
	case h.Root != "":
		return fmt.Sprintf("the plan sets no version constraint for it, and %s has no %s", h.Root, lock)
	}
	return fmt.Sprintf("the plan sets no version constraint for it, and no --terraform-root names a directory with a %s", lock)
}

// ProviderChoice is the provider version a run reads requirements for.
type ProviderChoice struct {
	// Ref is the embedded table's ref for that version, such as "v5.100.0".
	Ref string
	// Notice, when set, is a line to tell the user: the hints did not name a
	// version the table has, so the run reads Ref instead.
	Notice string
}

// ChooseProviderRef picks the embedded table's ref for the hints. An explicit
// version wins and must be a major version the table has. Otherwise the lock
// file's version decides, then the plan's constraints, when they admit only
// one of the table's majors. When neither names one, the run reads the
// nearest version the table has, the newest when there is no telling, and
// says so in the notice.
func ChooseProviderRef(h VersionHints) (ProviderChoice, error) {
	tbl, err := permdata.Embedded().Table()
	if err != nil {
		return ProviderChoice{}, err
	}
	newest := tbl.Newest()
	notice := func(format string, args ...any) ProviderChoice {
		return ProviderChoice{Ref: newest, Notice: fmt.Sprintf("terraform-permcheck: "+format, args...)}
	}

	if h.Explicit != "" {
		major, ok := providerversion.Major(h.Explicit)
		if !ok {
			return ProviderChoice{}, fmt.Errorf("%s %q: want a provider version such as 5 or 5.100.0", h.ExplicitFrom, h.Explicit)
		}
		ref, ok := tbl.RefFor(major)
		if !ok {
			return ProviderChoice{}, fmt.Errorf("%s %q: the embedded permissions table holds AWS provider %s only", h.ExplicitFrom, h.Explicit, strings.Join(tbl.Refs, " and "))
		}
		return ProviderChoice{Ref: ref}, nil
	}

	if h.Locked != "" {
		major, ok := providerversion.Major(h.Locked)
		if !ok {
			return notice("the lock file pins AWS provider %q, which is not a version; checking against provider %s.", h.Locked, newest), nil
		}
		if ref, ok := tbl.RefFor(major); ok {
			return ProviderChoice{Ref: ref}, nil
		}
		nearest := newest
		if oldest := tbl.Refs[0]; major < majorOf(oldest) {
			nearest = oldest
		}
		c := notice("the lock file pins AWS provider %s, and the embedded table has no %d.x; checking against provider %s.", h.Locked, major, nearest)
		c.Ref = nearest
		return c, nil
	}

	if len(h.Constraints) > 0 {
		var admitted []string
		for _, ref := range tbl.Refs {
			if providerversion.Admits(h.Constraints, majorOf(ref)) {
				admitted = append(admitted, ref)
			}
		}
		switch {
		case len(admitted) == 1:
			return ProviderChoice{Ref: admitted[0]}, nil
		case len(admitted) > 1:
			c := notice("no AWS provider version found: the plan's constraint %s admits provider %s, and no lock file names one. Checking against provider %s; set --aws-provider-version to choose.",
				quoteAll(h.Constraints), strings.Join(admitted, " and "), admitted[len(admitted)-1])
			c.Ref = admitted[len(admitted)-1]
			return c, nil
		}
		// The constraints admit no major the table has. Read the version
		// nearest to the ones they admit.
		nearest := newest
		oldest := tbl.Refs[0]
		for m := 0; m < majorOf(oldest); m++ {
			if providerversion.Admits(h.Constraints, m) {
				nearest = oldest
				break
			}
		}
		c := notice("the plan's AWS provider constraint %s admits no version the embedded table has; checking against provider %s.", quoteAll(h.Constraints), nearest)
		c.Ref = nearest
		return c, nil
	}

	return notice("no AWS provider version found: %s. Checking against provider %s; set --aws-provider-version to choose.", h.unknown(), newest), nil
}

func majorOf(ref string) int {
	m, _ := providerversion.Major(ref)
	return m
}

func quoteAll(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, " and ")
}
