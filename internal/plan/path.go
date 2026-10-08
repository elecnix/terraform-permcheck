package plan

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
)

// pathState keeps the decoded plan state of a resource change, so a gate on
// a nested attribute path such as ttl.0.enabled can read the nested value.
// The top-level maps of ResourceChange cannot answer for such a path.
type pathState struct {
	// state and unknown answer presence: the planned state and its
	// after_unknown, or the prior state and nil for a pure delete.
	state, unknown any
	// before, after and afterUnknown answer change. after is nil when the
	// plan has no planned state, and then change is unknown.
	before, after, afterUnknown any
}

// decodeState decodes a raw state for path walking. A value that does not
// decode reads as absent.
func decodeState(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

// PathPresent reports whether the attribute at a dotted path, such as
// ttl.0.enabled, holds a non-zero value, following d.GetOk. A path that
// reaches a value computed at apply time counts as present. known is false
// when the change carries no state, and then present means nothing.
func (rc *ResourceChange) PathPresent(path string) (present, known bool) {
	if rc.paths == nil || rc.paths.state == nil {
		return false, false
	}
	if unknownAlong(rc.paths.unknown, path) {
		return true, true
	}
	v, _ := walk(rc.paths.state, path)
	raw, err := json.Marshal(v)
	if err != nil {
		return true, true
	}
	return isMeaningful(raw), true
}

// PathChanged reports whether the attribute at a dotted path differs between
// the prior and the planned state, following d.HasChange. A path that reaches
// a value computed at apply time counts as changed. known is false when the
// change carries no planned state.
func (rc *ResourceChange) PathChanged(path string) (changed, known bool) {
	if rc.paths == nil || rc.paths.after == nil {
		return false, false
	}
	if unknownAlong(rc.paths.afterUnknown, path) {
		return true, true
	}
	b, _ := walk(rc.paths.before, path)
	a, _ := walk(rc.paths.after, path)
	return !reflect.DeepEqual(b, a), true
}

// walk follows a dotted path through objects and lists. A segment that is a
// number indexes a list. It reports false when the path leaves the value.
func walk(v any, path string) (any, bool) {
	for _, seg := range strings.Split(path, ".") {
		switch node := v.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			v = node[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// unknownAlong reports whether after_unknown marks the value at path, or any
// value that contains it, as computed at apply time.
func unknownAlong(unknown any, path string) bool {
	v := unknown
	for _, seg := range strings.Split(path, ".") {
		if b, ok := v.(bool); ok {
			return b
		}
		next, ok := walk(v, seg)
		if !ok {
			return false
		}
		v = next
	}
	b, _ := v.(bool)
	return b
}
