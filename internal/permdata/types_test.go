package permdata

import (
	"strings"
	"testing"
)

// TestEmbedded_SecurityHubAccountV2 checks that a resource type added in
// provider 6.x resolves from the embedded table. aws_securityhub_account_v2
// (internal/service/securityhub/account_v2.go) is a framework resource with
// @Tags: Create calls EnableSecurityHubV2, Read calls DescribeSecurityHubV2,
// Delete calls DisableSecurityHubV2, and transparent tagging lists tags on
// read and tags or untags on update. The resource has no Update method, so
// update holds only the tagging calls.
func TestEmbedded_SecurityHubAccountV2(t *testing.T) {
	s, err := Embedded().Resolve("aws_securityhub_account_v2")
	if err != nil {
		t.Fatalf("Resolve(aws_securityhub_account_v2): %v", err)
	}
	for op, want := range map[string][]string{
		"create": {"securityhub:EnableSecurityHubV2"},
		"read":   {"securityhub:DescribeSecurityHubV2", "securityhub:ListTagsForResource"},
		"update": {"securityhub:TagResource", "securityhub:UntagResource"},
		"delete": {"securityhub:DisableSecurityHubV2"},
	} {
		got := s.Actions(op)
		for _, action := range want {
			if !contains(got, action) {
				t.Errorf("%s = %v, want %s", op, got, action)
			}
		}
		for _, action := range got {
			if !strings.HasPrefix(action, "securityhub:") {
				t.Errorf("%s lists %s, want only securityhub actions", op, action)
			}
		}
	}
}

// TestEmbedded_GuardDutyDetectorFeature checks that aws_guardduty_detector_feature
// still resolves from the embedded table. Its file registers it under a
// function name the parser missed until #182.
func TestEmbedded_GuardDutyDetectorFeature(t *testing.T) {
	s, err := Embedded().Resolve("aws_guardduty_detector_feature")
	if err != nil {
		t.Fatalf("Resolve(aws_guardduty_detector_feature): %v", err)
	}
	for op, action := range map[string]string{
		"create": "guardduty:UpdateDetector",
		"read":   "guardduty:GetDetector",
		"update": "guardduty:UpdateDetector",
	} {
		if got := s.Actions(op); !contains(got, action) {
			t.Errorf("%s = %v, want %s", op, got, action)
		}
	}
}
