package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// TestLoad_Valid parses a well-formed config file.
func TestLoad_Valid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	body := `{
  "exclude": [
    { "permission": "s3:DeleteBucketPublicAccessBlock", "reason": "audit role" },
    { "permission": "secretsmanager:*", "resource": "aws_secretsmanager_*" }
  ]
}`
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Exclude) != 2 {
		t.Fatalf("got %d exclusions, want 2", len(cfg.Exclude))
	}
	if cfg.Exclude[0].Reason != "audit role" || cfg.Exclude[1].Resource != "aws_secretsmanager_*" {
		t.Errorf("unexpected parse: %+v", cfg.Exclude)
	}
}

// TestLoad_MissingPermission rejects an exclusion without a permission.
func TestLoad_MissingPermission(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	if err := os.WriteFile(p, []byte(`{"exclude":[{"reason":"no permission"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "permission is required") {
		t.Fatalf("expected 'permission is required' error, got %v", err)
	}
}

// TestLoad_BadJSON reports a parse error.
func TestLoad_BadJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

// TestLoad_BadPattern rejects an invalid glob pattern.
func TestLoad_BadPattern(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	if err := os.WriteFile(p, []byte(`{"exclude":[{"permission":"s3:[bad"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected invalid pattern error, got nil")
	}
}

// TestParse_Operations parses the optional list.
func TestParse_Operations(t *testing.T) {
	cfg, err := parse([]byte(`{"exclude":[
		{"permission":"s3:DeleteBucketEncryption","operations":["delete"],"reason":"locked bucket"},
		{"permission":"s3:*"}
	]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Exclude[0].Operations) != 1 || cfg.Exclude[0].Operations[0] != "delete" {
		t.Errorf("operations = %+v, want [delete]", cfg.Exclude[0].Operations)
	}
	if cfg.Exclude[1].Operations != nil {
		t.Errorf("absent operations = %+v, want nil", cfg.Exclude[1].Operations)
	}
}

// TestParse_OperationsNormalized pins that the trimmed, lowercased
// operation names land in the returned config, so a caller reading
// Config.Exclude[i].Operations never sees "Delete" or " delete ".
func TestParse_OperationsNormalized(t *testing.T) {
	cfg, err := parse([]byte(`{"exclude":[{"permission":"s3:*","operations":["Delete"," UPDATE "]}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"delete", "update"}
	if !slices.Equal(cfg.Exclude[0].Operations, want) {
		t.Fatalf("operations = %q, want %q", cfg.Exclude[0].Operations, want)
	}
}

// TestParse_UnknownOperation rejects a name the plan never emits.
func TestParse_UnknownOperation(t *testing.T) {
	_, err := parse([]byte(`{"exclude":[{"permission":"s3:*","operations":["destroy"]}]}`))
	if err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("expected 'unknown operation' error, got %v", err)
	}
}

// TestLoad_OperationsFile reads an operations list from disk.
func TestLoad_OperationsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permcheck.json")
	body := `{"exclude":[{"permission":"s3:DeleteBucketEncryption","resource":"aws_s3_bucket_server_side_encryption_configuration.*","operations":["delete"],"reason":"role intentionally cannot delete"}]}`
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e := cfg.Exclude[0]
	if len(e.Operations) != 1 || e.Operations[0] != "delete" {
		t.Fatalf("operations = %+v, want [delete]", e.Operations)
	}
}

func TestParse_Needs(t *testing.T) {
	c, err := parse([]byte(`{"needs":[{"sid":"Auth","principal":"ci","actions":["ecr:GetAuthorizationToken"],"resources":["*"],"reason":"docker login"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []iam.Need{{Sid: "Auth", Principal: "ci", Actions: []string{"ecr:GetAuthorizationToken"}, Resources: []string{"*"}, Reason: "docker login"}}
	if !reflect.DeepEqual(c.Needs, want) {
		t.Errorf("Needs = %+v, want %+v", c.Needs, want)
	}

	for _, tt := range []struct{ raw, want string }{
		{`{"needs":[{"actions":["s3:GetObject"]}]}`, "sid is required"},
		{`{"needs":[{"sid":"A"}]}`, "actions is required"},
		{`{"needs":[{"sid":"A","actions":["GetObject"]}]}`, "single service:Action"},
		{`{"needs":[{"sid":"A","actions":["s3:Get*"]}]}`, "single service:Action"},
		{`{"needs":[{"sid":"A","actions":["s3:GetObject"],"resources":["my-bucket"]}]}`, "must be \"*\" or an ARN"},
		{`{"needs":[{"sid":"A","actions":["s3:GetObject"]},{"sid":"A","actions":["s3:PutObject"]}]}`, "duplicate sid"},
		// A need without a principal runs with every principal, so its sid
		// clashes with the same sid under a named principal, in either order.
		{`{"needs":[{"sid":"A","actions":["s3:GetObject"]},{"sid":"A","principal":"ci","actions":["s3:PutObject"]}]}`, "duplicate sid"},
		{`{"needs":[{"sid":"A","principal":"ci","actions":["s3:GetObject"]},{"sid":"A","actions":["s3:PutObject"]}]}`, "duplicate sid"},
	} {
		if _, err := parse([]byte(tt.raw)); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("parse(%s): want error containing %q, got %v", tt.raw, tt.want, err)
		}
	}

	// Needs under two different principals never run together, so they may
	// share a sid.
	if _, err := parse([]byte(`{"needs":[{"sid":"A","principal":"ci","actions":["s3:GetObject"]},{"sid":"A","principal":"app","actions":["s3:PutObject"]}]}`)); err != nil {
		t.Errorf("parse: one sid under two principals: %v", err)
	}
}

func TestParse_StrictResources(t *testing.T) {
	c, err := parse([]byte(`{"strict_resources": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.StrictResources {
		t.Error("strict_resources not read from config")
	}
	c, err = parse([]byte(`{"exclude": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.StrictResources {
		t.Error("strict_resources must default to false")
	}
}

func TestParse_AllowUnresolvedTypes(t *testing.T) {
	cfg, err := parse([]byte(`{"allow_unresolved_types": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowUnresolvedTypes {
		t.Error("allow_unresolved_types not read")
	}
}
