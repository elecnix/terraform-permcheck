package provideraws

import "testing"

// cycleIndex builds a → b, c; b → a; and c uses a client. Every function
// reaches c, so every function reaches a client.
func cycleIndex() *pkgIndex {
	return &pkgIndex{
		clients: map[string]bool{"c": true},
		calls: map[string][]helperCall{
			"a": {{Name: "b"}, {Name: "c"}},
			"b": {{Name: "a"}},
		},
		reach: make(map[string]bool),
	}
}

// TestReachesClient_CycleDoesNotCacheFalse checks that a function inside a
// cycle is not stored as reaching no client because the search reached it
// while its caller was still being searched.
func TestReachesClient_CycleDoesNotCacheFalse(t *testing.T) {
	for _, order := range [][]string{{"a", "b"}, {"b", "a"}, {"a", "b", "c"}} {
		idx := cycleIndex()
		for _, name := range order {
			if !idx.reachesClient(name) {
				t.Errorf("order %v: reachesClient(%q) = false, want true", order, name)
			}
		}
	}
}

// TestReachesClient_NoClientInCycle checks that a cycle with no client
// anywhere still reports false, and caches it.
func TestReachesClient_NoClientInCycle(t *testing.T) {
	idx := &pkgIndex{
		clients: map[string]bool{},
		calls: map[string][]helperCall{
			"a": {{Name: "b"}},
			"b": {{Name: "a"}},
		},
		reach: make(map[string]bool),
	}
	for _, name := range []string{"a", "b", "a"} {
		if idx.reachesClient(name) {
			t.Errorf("reachesClient(%q) = true, want false", name)
		}
	}
}
