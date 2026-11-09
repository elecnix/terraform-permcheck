package permdata

import (
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// TestEmbedded_IAMRoleGetRolePolicyIsGatedOnInlinePolicy checks that the
// generated table carries the schemaGates correction for aws_iam_role:
// iam:GetRolePolicy must reach the validator with the inline_policy value
// guard, on every operation whose code path ends in the role read. Without the
// entry the parser lists it ungated, which reports it for every role.
func TestEmbedded_IAMRoleGetRolePolicyIsGatedOnInlinePolicy(t *testing.T) {
	s, err := Embedded().Resolve("aws_iam_role")
	if err != nil {
		t.Fatal(err)
	}

	want := iam.Gate{Attribute: "inline_policy", ValueGuarded: true}
	for _, op := range []string{"create", "read", "update"} {
		gates := s.Gates(op, "iam:GetRolePolicy")
		if len(gates) == 0 {
			t.Errorf("%s does not list iam:GetRolePolicy, want one gated path", op)
			continue
		}
		for i, g := range gates {
			if g != want {
				t.Errorf("%s iam:GetRolePolicy path %d gate = %+v, want %+v", op, i, g, want)
			}
		}
	}
}

// TestEmbedded_IAMRolePutRolePolicyKeepsItsGate checks that the correction
// leaves the sibling action the parser gated itself, so the two actions on the
// same path agree.
func TestEmbedded_IAMRolePutRolePolicyKeepsItsGate(t *testing.T) {
	s, err := Embedded().Resolve("aws_iam_role")
	if err != nil {
		t.Fatal(err)
	}
	want := iam.Gate{Attribute: "inline_policy", ValueGuarded: true}
	for _, g := range s.Gates("create", "iam:PutRolePolicy") {
		if g != want {
			t.Errorf("create iam:PutRolePolicy gate = %+v, want %+v", g, want)
		}
	}
}

// TestEmbedded_ACMImportCertificateIsGatedOnTheImportAttributes checks that
// the generated table gates create's acm:ImportCertificate on certificate_body
// and on the write-only private_key_wo. Ungated, it reports the import for a
// certificate requested by domain_name.
func TestEmbedded_ACMImportCertificateIsGatedOnTheImportAttributes(t *testing.T) {
	s, err := Embedded().Resolve("aws_acm_certificate")
	if err != nil {
		t.Fatal(err)
	}
	got := s.Gates("create", "acm:ImportCertificate")
	want := []iam.Gate{
		{Attribute: "certificate_body", ValueGuarded: true},
		{Attribute: "private_key_wo", ValueGuarded: true},
	}
	if len(got) != len(want) {
		t.Fatalf("create acm:ImportCertificate paths = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
