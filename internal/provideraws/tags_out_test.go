package provideraws

import (
	"os"
	"path/filepath"
	"testing"
)

// tagsOutServiceSrc is a service whose generated ListTags lists tags through
// the API. The provider's tag interceptor calls it after a create or read only
// when the resource's read did not set the tags itself with setTagsOut.
const tagsOutServiceSrc = `
package iam

import "github.com/aws/aws-sdk-go-v2/service/iam"

func listTags(ctx context.Context, conn *iam.Client, identifier string) error {
	_, err := conn.ListOpenIDConnectProviderTags(ctx, &iam.ListOpenIDConnectProviderTagsInput{})
	if err != nil {
		return err
	}
	return nil
}

func setTagsOut(ctx context.Context, tags []awstypes.Tag) {
}
`

// TestSourceProvider_NoListTagsWhenReadSetsTagsOut covers a resource whose read
// takes its tags from the API response. The interceptor then skips ListTags,
// so the list action is not a permission of read or create (issue #197).
func TestSourceProvider_NoListTagsWhenReadSetsTagsOut(t *testing.T) {
	const oidcSrc = `
package iam

import "github.com/aws/aws-sdk-go-v2/service/iam"

// @SDKResource("aws_iam_openid_connect_provider", name="OIDC Provider")
// @Tags(identifierAttribute="id", resourceType="OIDCProvider")
func resourceOpenIDConnectProviderCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	_, err := conn.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{})
	if err != nil { return nil }
	return append(diags, resourceOpenIDConnectProviderRead(ctx, d, meta)...)
}

func resourceOpenIDConnectProviderRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	output, err := conn.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{})
	if err != nil { return nil }
	resourceOpenIDConnectProviderFlatten(ctx, output, d)
	return diags
}

func resourceOpenIDConnectProviderFlatten(ctx context.Context, provider *iam.GetOpenIDConnectProviderOutput, d *schema.ResourceData) {
	d.Set("url", provider.Url)
	setTagsOut(ctx, provider.Tags)
}

func resourceOpenIDConnectProviderDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	_, err := conn.DeleteOpenIDConnectProvider(ctx, &iam.DeleteOpenIDConnectProviderInput{})
	if err != nil { return nil }
	return nil
}
`
	// The read sets the tags only when the response has any: the interceptor
	// may still list them.
	const conditionalSrc = `
package iam

import "github.com/aws/aws-sdk-go-v2/service/iam"

// @SDKResource("aws_iam_conditional", name="Conditional")
// @Tags(identifierAttribute="id")
func resourceConditionalCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	_, err := conn.CreateOpenIDConnectProvider(ctx, &iam.CreateOpenIDConnectProviderInput{})
	if err != nil { return nil }
	return resourceConditionalRead(ctx, d, meta)
}

func resourceConditionalRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).IAMClient(ctx)
	output, err := conn.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{})
	if err != nil { return nil }
	if len(output.Tags) > 0 {
		setTagsOut(ctx, output.Tags)
	}
	return nil
}

func resourceConditionalDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	return nil
}
`
	dir := t.TempDir()
	svc := filepath.Join(dir, "internal", "service", "iam")
	if err := os.MkdirAll(svc, 0755); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"openid_connect_provider.go": oidcSrc,
		"conditional.go":             conditionalSrc,
		"tags_gen.go":                tagsOutServiceSrc,
	} {
		if err := os.WriteFile(filepath.Join(svc, name), []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
	}
	p := NewSourceProviderWithPath(dir)

	oidc, err := p.Resolve("aws_iam_openid_connect_provider")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	for _, op := range []string{"create", "read"} {
		if got := oidc.Actions(op); contains(got, "iam:ListOpenIDConnectProviderTags") {
			t.Errorf("%s = %v, want no iam:ListOpenIDConnectProviderTags: the read sets the tags", op, got)
		}
	}

	cond, err := p.Resolve("aws_iam_conditional")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	for _, op := range []string{"create", "read"} {
		if got := cond.Actions(op); !contains(got, "iam:ListOpenIDConnectProviderTags") {
			t.Errorf("%s = %v, want iam:ListOpenIDConnectProviderTags: setTagsOut runs under a condition", op, got)
		}
	}
}
