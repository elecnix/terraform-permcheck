package provideraws

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/cloud"
	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// API Gateway authorizes by HTTP verb, under the apigateway prefix for both
// the v1 (REST) and v2 (HTTP and WebSocket) APIs. These fixtures are trimmed
// from terraform-provider-aws v5.90.0 internal/service/apigatewayv2.

const apigatewayv2DomainNameSrc = `
package apigatewayv2

import (
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// @SDKResource("aws_apigatewayv2_domain_name", name="Domain Name")
// @Tags(identifierAttribute="arn")
func resourceDomainName() *schema.Resource {
	return &schema.Resource{}
}

func resourceDomainNameCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).APIGatewayV2Client(ctx)

	domainName := d.Get(names.AttrDomainName).(string)
	input := &apigatewayv2.CreateDomainNameInput{
		DomainName: aws.String(domainName),
		Tags:       getTagsIn(ctx),
	}

	output, err := conn.CreateDomainName(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating API Gateway v2 Domain Name (%s): %s", domainName, err)
	}

	d.SetId(aws.ToString(output.DomainName))

	if _, err := waitDomainNameAvailable(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for API Gateway v2 Domain Name (%s) create: %s", d.Id(), err)
	}

	return append(diags, resourceDomainNameRead(ctx, d, meta)...)
}

func resourceDomainNameRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).APIGatewayV2Client(ctx)

	output, err := findDomainName(ctx, conn, d.Id())

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading API Gateway v2 Domain Name (%s): %s", d.Id(), err)
	}

	d.Set(names.AttrDomainName, output.DomainName)

	return diags
}

func resourceDomainNameUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).APIGatewayV2Client(ctx)

	if d.HasChanges("domain_name_configuration", "mutual_tls_authentication") {
		input := &apigatewayv2.UpdateDomainNameInput{
			DomainName: aws.String(d.Id()),
		}

		_, err := conn.UpdateDomainName(ctx, input)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating API Gateway v2 Domain Name (%s): %s", d.Id(), err)
		}
	}

	return append(diags, resourceDomainNameRead(ctx, d, meta)...)
}

func resourceDomainNameDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).APIGatewayV2Client(ctx)

	input := apigatewayv2.DeleteDomainNameInput{
		DomainName: aws.String(d.Id()),
	}
	_, err := conn.DeleteDomainName(ctx, &input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting API Gateway v2 Domain Name (%s): %s", d.Id(), err)
	}

	return diags
}

func findDomainName(ctx context.Context, conn *apigatewayv2.Client, name string) (*apigatewayv2.GetDomainNameOutput, error) {
	input := &apigatewayv2.GetDomainNameInput{
		DomainName: aws.String(name),
	}

	output, err := conn.GetDomainName(ctx, input)

	if err != nil {
		return nil, err
	}

	return output, nil
}

func waitDomainNameAvailable(ctx context.Context, conn *apigatewayv2.Client, name string, timeout time.Duration) (*apigatewayv2.GetDomainNameOutput, error) {
	return findDomainName(ctx, conn, name)
}
`

const apigatewayv2TagsGenSrc = `
package apigatewayv2

import (
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

func listTags(ctx context.Context, conn *apigatewayv2.Client, identifier string, optFns ...func(*apigatewayv2.Options)) (tftags.KeyValueTags, error) {
	input := apigatewayv2.GetTagsInput{
		ResourceArn: aws.String(identifier),
	}

	output, err := conn.GetTags(ctx, &input, optFns...)

	if err != nil {
		return tftags.New(ctx, nil), err
	}

	return KeyValueTags(ctx, output.Tags), nil
}

func updateTags(ctx context.Context, conn *apigatewayv2.Client, identifier string, oldTagsMap, newTagsMap any, optFns ...func(*apigatewayv2.Options)) error {
	oldTags := tftags.New(ctx, oldTagsMap)
	newTags := tftags.New(ctx, newTagsMap)

	removedTags := oldTags.Removed(newTags)
	if len(removedTags) > 0 {
		input := apigatewayv2.UntagResourceInput{
			ResourceArn: aws.String(identifier),
			TagKeys:     removedTags.Keys(),
		}

		_, err := conn.UntagResource(ctx, &input, optFns...)

		if err != nil {
			return fmt.Errorf("untagging resource (%s): %w", identifier, err)
		}
	}

	updatedTags := oldTags.Updated(newTags)
	if len(updatedTags) > 0 {
		input := apigatewayv2.TagResourceInput{
			ResourceArn: aws.String(identifier),
			Tags:        Tags(updatedTags),
		}

		_, err := conn.TagResource(ctx, &input, optFns...)

		if err != nil {
			return fmt.Errorf("tagging resource (%s): %w", identifier, err)
		}
	}

	return nil
}
`

func TestSDKMethodToIAMAction_APIGatewayHTTPVerbs(t *testing.T) {
	tests := []struct {
		method  string
		service string
		want    string
	}{
		// v2 (HTTP and WebSocket APIs)
		{"CreateDomainName", "apigatewayv2", "apigateway:POST"},
		{"CreateApiMapping", "apigatewayv2", "apigateway:POST"},
		{"GetDomainName", "apigatewayv2", "apigateway:GET"},
		{"GetApiMapping", "apigatewayv2", "apigateway:GET"},
		{"UpdateDomainName", "apigatewayv2", "apigateway:PATCH"},
		{"DeleteApiMapping", "apigatewayv2", "apigateway:DELETE"},
		{"TagResource", "apigatewayv2", "apigateway:POST"},
		{"UntagResource", "apigatewayv2", "apigateway:DELETE"},
		{"GetTags", "apigatewayv2", "apigateway:GET"},
		{"ImportApi", "apigatewayv2", "apigateway:PUT"},
		{"ReimportApi", "apigatewayv2", "apigateway:PUT"},
		{"ExportApi", "apigatewayv2", "apigateway:GET"},
		{"ResetAuthorizersCache", "apigatewayv2", "apigateway:DELETE"},
		// v1 (REST APIs)
		{"CreateRestApi", "apigateway", "apigateway:POST"},
		{"PutRestApi", "apigateway", "apigateway:PUT"},
		{"UpdateRestApi", "apigateway", "apigateway:PATCH"},
		{"DeleteRestApi", "apigateway", "apigateway:DELETE"},
		{"TagResource", "apigateway", "apigateway:PUT"},
		{"UntagResource", "apigateway", "apigateway:DELETE"},
		{"GetTags", "apigateway", "apigateway:GET"},
		{"FlushStageCache", "apigateway", "apigateway:DELETE"},
		{"ImportRestApi", "apigateway", "apigateway:POST"},
		{"ImportDocumentationParts", "apigateway", "apigateway:PUT"},
		{"GenerateClientCertificate", "apigateway", "apigateway:POST"},
	}
	for _, tt := range tests {
		t.Run(tt.service+"."+tt.method, func(t *testing.T) {
			if got := sdKMethodToIAMAction(tt.method, tt.service); got != tt.want {
				t.Errorf("sdKMethodToIAMAction(%q, %q) = %q, want %q", tt.method, tt.service, got, tt.want)
			}
		})
	}
}

func TestExtractTagActions_APIGatewayV2(t *testing.T) {
	ta, err := ExtractTagActions(apigatewayv2TagsGenSrc)
	if err != nil {
		t.Fatalf("ExtractTagActions failed: %v", err)
	}
	if !contains(ta.Apply, "apigateway:POST") || len(ta.Apply) != 1 {
		t.Errorf("Apply = %v, want [apigateway:POST]", ta.Apply)
	}
	if !contains(ta.Remove, "apigateway:DELETE") || len(ta.Remove) != 1 {
		t.Errorf("Remove = %v, want [apigateway:DELETE]", ta.Remove)
	}
	if !contains(ta.List, "apigateway:GET") || len(ta.List) != 1 {
		t.Errorf("List = %v, want [apigateway:GET]", ta.List)
	}
}

// TestSourceProvider_APIGatewayV2DomainName checks the whole source path for
// an API Gateway v2 resource: every action carries the apigateway prefix and
// an HTTP verb, and the create call's POST stays required when the tagging
// call also maps to POST.
func TestSourceProvider_APIGatewayV2DomainName(t *testing.T) {
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "internal", "service", "apigatewayv2")
	if err := os.MkdirAll(svcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svcDir, "domain_name.go"), []byte(apigatewayv2DomainNameSrc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(svcDir, "tags_gen.go"), []byte(apigatewayv2TagsGenSrc), 0644); err != nil {
		t.Fatal(err)
	}

	schema, err := NewSourceProviderWithPath(dir).Resolve("aws_apigatewayv2_domain_name")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	want := map[string][]string{
		"create": {"apigateway:POST", "apigateway:GET"},
		"read":   {"apigateway:GET"},
		"update": {"apigateway:PATCH", "apigateway:POST", "apigateway:DELETE"},
		"delete": {"apigateway:DELETE"},
	}
	for op, actions := range want {
		for _, a := range actions {
			if !contains(schema.Permissions[op], a) {
				t.Errorf("%s: expected %s, got %v", op, a, schema.Permissions[op])
			}
		}
	}
	for op, actions := range schema.Permissions {
		for _, a := range actions {
			verb := strings.TrimPrefix(a, "apigateway:")
			if verb == a || verb != strings.ToUpper(verb) {
				t.Errorf("%s: %s is not an apigateway HTTP verb action", op, a)
			}
		}
	}
	// CreateDomainName needs POST whether or not tags are set, so the tagging
	// call's tags gate must not attach to it.
	if cond := schema.Conditional["create"]["apigateway:POST"]; cond != "" {
		t.Errorf("create: apigateway:POST gated on %q, want unconditional", cond)
	}
}

// TestAddTagActions_SharedVerb covers a tagging action that the resource's
// own calls already need. API Gateway v1 authorizes PutRestApi (gated on
// body) and TagResource (gated on tags) as the same apigateway:PUT, so the
// action is needed when either attribute is set. An action one call makes
// with no gate stays ungated.
func TestAddTagActions_SharedVerb(t *testing.T) {
	schema := &cloud.Schema{
		Permissions: map[string][]string{"create": {"apigateway:POST", "apigateway:PUT", "apigateway:PATCH"}},
		Conditional: map[string]map[string]string{"create": {"apigateway:PUT": "body"}},
		ChangeGated: map[string]map[string]string{"create": {"apigateway:PATCH": "body"}},
	}
	addTagActions(schema, "create", []string{"apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE"})

	if got := schema.Permissions["create"]; len(got) != 4 {
		t.Errorf("create = %v, want POST, PUT, PATCH and DELETE once each", got)
	}
	if gate := schema.Conditional["create"]["apigateway:POST"]; gate != "" || schema.Gates["create"]["apigateway:POST"] != nil {
		t.Errorf("apigateway:POST gated, want ungated")
	}
	wantGates := map[string][]iam.Gate{
		"apigateway:PUT":   {{Attribute: "body"}, {Attribute: "tags"}},
		"apigateway:PATCH": {{Changed: "body"}, {Attribute: "tags"}},
	}
	for action, want := range wantGates {
		got := schema.Gates["create"][action]
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s gates = %+v, want %+v", action, got, want)
		}
		if schema.Conditional["create"][action] != "" || schema.ChangeGated["create"][action] != "" {
			t.Errorf("%s keeps a single-valued gate beside its gate list", action)
		}
	}
	if gate := schema.Conditional["create"]["apigateway:DELETE"]; gate != "tags" {
		t.Errorf("apigateway:DELETE gated on %q, want tags", gate)
	}
}
