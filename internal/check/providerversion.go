package check

import (
	"fmt"
	"strings"

	"github.com/elecnix/terraform-permcheck/internal/permdata"
	"github.com/elecnix/terraform-permcheck/internal/providerversion"
)

// ExplicitFromConfig is the VersionHints.ExplicitFrom of a version the config
// file set.
const ExplicitFromConfig = "aws_provider_version"

// VersionHints is what a run knows about the AWS provider version the plan
// or the terraform root uses, most authoritative first.
type VersionHints struct {
	// Explicit is the version the user set, such as "5", "5.100.0" or
	// "v6.72.0", or "". ExplicitFrom is where: "--aws-provider-version" or
	// ExplicitFromConfig.
	Explicit, ExplicitFrom string
	// Locked is the version a .terraform.lock.hcl pins, or "", and LockFile
	// is the path of that file.
	Locked, LockFile string
	// Constraints are the plan's version constraints for the provider.
	Constraints []string
	// Searched lists the directories whose .terraform.lock.hcl was looked
	// for and missing, as the notice should name them. Static is true in
	// static HCL mode, which reads no plan.
	Searched []string
	Static   bool
}

// unknown says why the hints name no version, for the notice.
func (h VersionHints) unknown() string {
	where := fmt.Sprintf("no %s in %s", providerversion.LockFile, strings.Join(h.Searched, " or "))
	if h.Static {
		return where
	}
	return "the plan sets no version constraint for it, and " + where
}

// ProviderChoice is the provider version a run reads requirements for.
type ProviderChoice struct {
	// Ref is the embedded table's ref for that version, such as "v5.100.0".
	Ref string
	// Notice is the line to tell the user: the version the run reads and
	// what named it, or why nothing named a version the table has.
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
	found := func(ref, source string) ProviderChoice {
		return ProviderChoice{Ref: ref, Notice: fmt.Sprintf("terraform-permcheck: checking against AWS provider %s: %s.", ref, source)}
	}
	fallback := func(ref, format string, args ...any) ProviderChoice {
		return ProviderChoice{Ref: ref, Notice: fmt.Sprintf("terraform-permcheck: "+format, args...)}
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
		if h.ExplicitFrom == ExplicitFromConfig {
			return found(ref, fmt.Sprintf("%s %q in the config", ExplicitFromConfig, h.Explicit)), nil
		}
		return found(ref, h.ExplicitFrom+" "+h.Explicit), nil
	}

	if h.Locked != "" {
		major, ok := providerversion.Major(h.Locked)
		if !ok {
			return fallback(newest, "%s pins AWS provider %q, which is not a version; checking against provider %s.", h.LockFile, h.Locked, newest), nil
		}
		if ref, ok := tbl.RefFor(major); ok {
			return found(ref, fmt.Sprintf("%s pins %s", h.LockFile, h.Locked)), nil
		}
		nearest := newest
		if oldest := tbl.Refs[0]; major < majorOf(oldest) {
			nearest = oldest
		}
		return fallback(nearest, "%s pins AWS provider %s, and the embedded table has no %d.x; checking against provider %s.", h.LockFile, h.Locked, major, nearest), nil
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
			return found(admitted[0], "the plan's "+constraintPhrase(h.Constraints)), nil
		case len(admitted) > 1:
			ref := admitted[len(admitted)-1]
			return fallback(ref, "no AWS provider version found: the plan's %s admits provider %s, and %s. Checking against provider %s; set --aws-provider-version to choose.",
				constraintPhrase(h.Constraints), strings.Join(admitted, " and "), h.missingLock(), ref), nil
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
		return fallback(nearest, "the plan's AWS provider %s admits no version the embedded table has; checking against provider %s.", constraintPhrase(h.Constraints), nearest), nil
	}

	return fallback(newest, "no AWS provider version found: %s. Checking against provider %s; set --aws-provider-version to choose.", h.unknown(), newest), nil
}

// missingLock says where no lock file was found.
func (h VersionHints) missingLock() string {
	return fmt.Sprintf("there is no %s in %s", providerversion.LockFile, strings.Join(h.Searched, " or "))
}

func majorOf(ref string) int {
	m, _ := providerversion.Major(ref)
	return m
}

// constraintPhrase names the plan's constraints, such as `constraint "~> 5.0"`.
func constraintPhrase(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = fmt.Sprintf("%q", s)
	}
	if len(q) == 1 {
		return "constraint " + q[0]
	}
	return "constraints " + strings.Join(q, " and ")
}
