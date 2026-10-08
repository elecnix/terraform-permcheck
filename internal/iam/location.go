package iam

import "regexp"

// FileLocation records the source file path and line number of a terraform
// resource declaration.
type FileLocation struct {
	Path string // file path relative to --terraform-root
	Line int    // 1-based line number of the resource declaration
}

// ResourceKey names a terraform resource block: its type, a dot, and its local
// name, such as "aws_s3_bucket.logs". It carries no count or for_each index,
// because one block declares every instance of the resource.
//
// The key has one producer and several readers. internal/hcl writes it from
// resource block labels, which never carry an index. The report and the
// exclusion matcher build it from plan addresses, which may carry one
// (aws_s3_bucket.logs[0]). Both sides call KeyOf, which strips the index, so
// the keys agree.
type ResourceKey string

// KeyOf returns the ResourceKey of a resource with the given type and name.
func KeyOf(resourceType, resourceName string) ResourceKey {
	return ResourceKey(resourceType + "." + stripResourceIndex(resourceName))
}

// Locations maps each resource block to the place that declares it.
type Locations map[ResourceKey]FileLocation

// Of returns where m's resource is declared. A finding from a declared need
// has no resource block, so it has no location.
func (l Locations) Of(m MissingAction) (FileLocation, bool) {
	if m.Need != "" {
		return FileLocation{}, false
	}
	loc, ok := l[KeyOf(m.ResourceType, m.ResourceName)]
	return loc, ok
}

// stripResourceIndex removes a count or for_each index suffix from a
// terraform resource name.
//
//	cloudtrail[0]       → cloudtrail
//	config["us-east-1"]  → config
func stripResourceIndex(name string) string {
	return resourceIndexRE.ReplaceAllString(name, "")
}

// resourceIndexRE matches a trailing bracket-index suffix like [0] or ["key"].
var resourceIndexRE = regexp.MustCompile(`\[[^\]]*\]$`)
