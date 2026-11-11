package provideraws

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// TestParseResourceFileStructured_GuardLocalFromBooleanExpression covers a
// local bound to a boolean expression over d.HasChange calls, as the S3 bucket
// update does in provider v6: the local carries the gates of its operands, so
// a call under it stays gated on the attributes it tests.
func TestParseResourceFileStructured_GuardLocalFromBooleanExpression(t *testing.T) {
	src := `
package s3

func resourceBucketUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).S3Client(ctx)

	aclChanged := d.HasChange("acl") && !d.IsNewResource() && deprecatedAttributeInRawConfig(d, "acl")
	grantEmptied := d.HasChange("grant") && d.Get("grant").(*schema.Set).Len() == 0 && deprecatedAttributeInRawConfig(d, "grant")
	if aclChanged || grantEmptied {
		_, err := conn.PutBucketAcl(ctx, &s3.PutBucketAclInput{})
		if err != nil { return nil }
	}

	// Both operands must hold, so the stronger gate stands.
	versioned := d.HasChange("versioning") && !d.IsNewResource()
	if versioned {
		_, err := conn.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{})
		if err != nil { return nil }
	}

	// An operand that tests no attribute makes the disjunction ungated.
	either := d.HasChange("logging") || d.IsNewResource()
	if either {
		_, err := conn.PutBucketLogging(ctx, &s3.PutBucketLoggingInput{})
		if err != nil { return nil }
	}

	// A local rebound to a non-guard stops carrying the gate.
	stale := d.HasChange("cors_rule") && !d.IsNewResource()
	stale = somethingElse()
	if stale {
		_, err := conn.PutBucketCors(ctx, &s3.PutBucketCorsInput{})
		if err != nil { return nil }
	}
	return nil
}
`
	actions, err := ParseResourceFileStructured(src, "aws_s3_bucket", "Bucket")
	if err != nil {
		t.Fatalf("ParseResourceFileStructured failed: %v", err)
	}
	checkGates(t, withoutErrorHandling(actions), "update", []gateCase{
		{"s3:PutBucketAcl", []iam.Gate{changed("acl"), changed("grant")}},
		{"s3:PutBucketVersioning", []iam.Gate{changed("versioning")}},
		{"s3:PutBucketLogging", always},
		{"s3:PutBucketCORS", always},
	})
}
