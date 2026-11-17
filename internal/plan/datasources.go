package plan

import (
	"encoding/json"
)

// DataSource is a data source of the plan, such as data.aws_iam_policy.ecr.
type DataSource struct {
	// Address is the full instance address as terraform prints it, such as
	// module.app.data.aws_iam_policy.ecr.
	Address string
	// ModuleAddress is the module the data source lives in. It is empty in
	// the root module.
	ModuleAddress string
	// Type is the data source type, such as aws_iam_policy.
	Type string
	// Name is the data source name, such as ecr.
	Name string
	// Values are the known, non-empty string values of its top-level
	// attributes. For a deferred read they are the arguments the plan
	// knows, and the attributes the provider reads are absent.
	Values map[string]string
	// Deferred is true when terraform reads the data source during the
	// apply, so the plan doesn't show what the read returns.
	Deferred bool
}

// tfDataPlanJSON mirrors the parts of a plan that record data sources.
//
// A capture of `terraform show -json` with terraform 1.15
// (testdata/datasource_capture) shows where they are. Terraform reads a data
// source during the plan when each argument is known and no dependency has a
// pending change. The plan then records its values in prior_state only, and
// neither resource_changes nor planned_values lists it. When an argument is
// known only after apply, or a depends_on names a resource with a pending
// change, terraform defers the read. The plan then lists the data source in
// resource_changes with the action read, its known arguments in after, and
// what the provider reads in after_unknown.
type tfDataPlanJSON struct {
	PriorState *struct {
		Values *struct {
			RootModule *tfStateModule `json:"root_module"`
		} `json:"values"`
	} `json:"prior_state"`
	ResourceChanges []tfResourceChange `json:"resource_changes"`
}

// tfStateModule mirrors a module of a state's values: its resources and its
// child modules.
type tfStateModule struct {
	Resources []struct {
		Address string                     `json:"address"`
		Mode    string                     `json:"mode"`
		Type    string                     `json:"type"`
		Name    string                     `json:"name"`
		Values  map[string]json.RawMessage `json:"values"`
	} `json:"resources"`
	Address      string          `json:"address"`
	ChildModules []tfStateModule `json:"child_modules"`
}

// ParseDataSources returns the data sources of raw terraform plan JSON: those
// terraform read during the plan, with their values, and those whose read it
// deferred to the apply. Parse skips data sources, since a read calls no
// mutating API. A policy check reads them for the text of a managed policy
// that the plan doesn't create.
func ParseDataSources(raw []byte) ([]DataSource, error) {
	var p tfDataPlanJSON
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	var out []DataSource
	deferred := map[string]bool{}
	for _, rc := range p.ResourceChanges {
		if rc.Mode != "data" {
			continue
		}
		fields, ok := stateFields(rc.Change.After)
		deferred[rc.Address] = true
		out = append(out, DataSource{
			Address:       rc.Address,
			ModuleAddress: rc.ModuleAddress,
			Type:          rc.Type,
			Name:          rc.Name,
			Values:        attributeStringValues(fields, ok),
			Deferred:      true,
		})
	}
	if p.PriorState == nil || p.PriorState.Values == nil || p.PriorState.Values.RootModule == nil {
		return out, nil
	}
	var walk func(m *tfStateModule)
	walk = func(m *tfStateModule) {
		for _, r := range m.Resources {
			// A deferred read replaces the value an earlier apply stored.
			if r.Mode != "data" || deferred[r.Address] {
				continue
			}
			out = append(out, DataSource{
				Address:       r.Address,
				ModuleAddress: m.Address,
				Type:          r.Type,
				Name:          r.Name,
				Values:        attributeStringValues(r.Values, r.Values != nil),
			})
		}
		for i := range m.ChildModules {
			walk(&m.ChildModules[i])
		}
	}
	walk(p.PriorState.Values.RootModule)
	return out, nil
}
