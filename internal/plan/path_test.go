package plan

import "testing"

// nestedPlan has a table created with ttl enabled and point-in-time recovery
// disabled, and a stream whose mode changes on update.
const nestedPlan = `{"resource_changes":[
{"type":"aws_dynamodb_table","name":"t","change":{"actions":["create"],"before":null,
 "after":{"ttl":[{"enabled":true,"attribute_name":"exp"}],"point_in_time_recovery":[{"enabled":false}],"replica":[]},
 "after_unknown":{"ttl":[{"attribute_name":true}],"arn":true}}},
{"type":"aws_kinesis_stream","name":"s","change":{"actions":["update"],
 "before":{"stream_mode_details":[{"stream_mode":"PROVISIONED"}],"retention_period":24},
 "after":{"stream_mode_details":[{"stream_mode":"ON_DEMAND"}],"retention_period":24},
 "after_unknown":{}}},
{"type":"aws_kinesis_stream","name":"gone","change":{"actions":["delete"],
 "before":{"stream_mode_details":[{"stream_mode":"PROVISIONED"}]},"after":null}}
]}`

func TestPathPresentAndChanged(t *testing.T) {
	changes, err := Parse([]byte(nestedPlan), "")
	if err != nil {
		t.Fatal(err)
	}
	table, stream, gone := changes[0], changes[1], changes[2]
	present := []struct {
		rc          *ResourceChange
		path        string
		want, known bool
	}{
		{table, "ttl.0.enabled", true, true},
		{table, "point_in_time_recovery.0.enabled", false, true},
		{table, "replica.0.region_name", false, true},
		{table, "ttl.0.attribute_name", true, true}, // computed at apply time
		{table, "ttl", true, true},
		{table, "missing.0.x", false, true},
		{gone, "stream_mode_details.0.stream_mode", true, true},
	}
	for _, c := range present {
		got, known := c.rc.PathPresent(c.path)
		if got != c.want || known != c.known {
			t.Errorf("%s PathPresent(%q) = %v, %v; want %v, %v", c.rc.Name, c.path, got, known, c.want, c.known)
		}
	}
	changed := []struct {
		rc          *ResourceChange
		path        string
		want, known bool
	}{
		{stream, "stream_mode_details.0.stream_mode", true, true},
		{stream, "retention_period", false, true},
		{table, "ttl.0.enabled", true, true},
		{table, "point_in_time_recovery.0.enabled", true, true},
		{table, "ttl.0.attribute_name", true, true},
		{gone, "stream_mode_details.0.stream_mode", false, false},
	}
	for _, c := range changed {
		got, known := c.rc.PathChanged(c.path)
		if got != c.want || known != c.known {
			t.Errorf("%s PathChanged(%q) = %v, %v; want %v, %v", c.rc.Name, c.path, got, known, c.want, c.known)
		}
	}
	// A resource change built without plan state knows nothing.
	if _, known := (&ResourceChange{}).PathPresent("ttl.0.enabled"); known {
		t.Error("PathPresent on a change with no state is known")
	}
}
