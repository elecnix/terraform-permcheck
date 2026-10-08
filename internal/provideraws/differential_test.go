package provideraws

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// TestParseResourceFileStructured_MatchesPreRefactorWalker is the differential
// test for this refactor.
//
// Three Cite findings on this PR claimed that merging walkWithConditionals and
// walkForHelpers into one traversal changed behaviour: that an else branch
// inherits the guard's conditional context, that a nested guard no longer
// keeps the outer condition reason, and that a client assignment inside an
// if-block no longer persists.
//
// The goldens below were captured from the pre-refactor implementation on main
// (walkWithConditionals + walkForHelpers, before they were merged). If this
// refactor is behaviour-preserving, the merged traversal reproduces them
// exactly. A difference here is a real regression, not a matter of opinion.
var fixtures = map[string]string{
	"nestedGuards": `package p
func resourceXCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	if _, ok := d.GetOk("outer"); ok {
		if _, ok := d.GetOk("inner"); ok {
			conn.PutBackupVaultAccessPolicy(ctx, nil)
		}
		conn.DeleteBackupVault(ctx, nil)
	}
	conn.TagResource(ctx, nil)
	return nil
}`,
	"plainIfReassign": `package p
func resourceXCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	if err != nil {
		kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
		kmsConn.CreateGrant(ctx, nil)
	}
	conn.CreateBackupVault(ctx, nil)
	return nil
}`,
	"guardReassign": `package p
func resourceXCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	if _, ok := d.GetOk("kms_key_arn"); ok {
		kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
		kmsConn.CreateGrant(ctx, nil)
	}
	conn.TagResource(ctx, nil)
	return nil
}`,
	"elseIfChain": `package p
func resourceXCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	if d.Get("primary").(bool) {
		conn.DeleteBackupVaultCopyPoint(ctx, nil)
	} else if d.Get("secondary").(bool) {
		conn.StartBackupVaultCopyPoint(ctx, nil)
	} else {
		conn.DescribeCopyPoint(ctx, nil)
	}
	return nil
}`,
	"serviceSwitch": `package p
func resourceXCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if d.Get("use_kms").(bool) {
		kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
		kmsConn.CreateGrant(ctx, nil)
	} else {
		conn := meta.(*conns.AWSClient).BackupClient(ctx)
		conn.CreateBackupVault(ctx, nil)
	}
	return nil
}`,
}

// legacyGoldens was produced by running the same fixtures through the
// pre-refactor parser on main, serialised with encoding/json.
const legacyGoldens = `{
  "elseIfChain": {
    "create": [
      {
        "Action": "backup:DeleteBackupVaultCopyPoint",
        "Conditional": true,
        "Condition": "primary"
      },
      {
        "Action": "backup:StartBackupVaultCopyPoint",
        "Conditional": true,
        "Condition": "primary"
      },
      {
        "Action": "backup:DescribeCopyPoint",
        "Conditional": true,
        "Condition": "primary"
      }
    ]
  },
  "guardReassign": {
    "create": [
      {
        "Action": "kms:CreateGrant",
        "Conditional": true,
        "Condition": "kms_key_arn"
      },
      {
        "Action": "backup:TagResource",
        "Conditional": false,
        "Condition": ""
      }
    ]
  },
  "nestedGuards": {
    "create": [
      {
        "Action": "backup:PutBackupVaultAccessPolicy",
        "Conditional": true,
        "Condition": "outer"
      },
      {
        "Action": "backup:DeleteBackupVault",
        "Conditional": true,
        "Condition": "outer"
      },
      {
        "Action": "backup:TagResource",
        "Conditional": false,
        "Condition": ""
      }
    ]
  },
  "plainIfReassign": {
    "create": [
      {
        "Action": "kms:CreateGrant",
        "Conditional": false,
        "Condition": ""
      },
      {
        "Action": "backup:CreateBackupVault",
        "Conditional": false,
        "Condition": ""
      }
    ]
  },
  "serviceSwitch": {
    "create": [
      {
        "Action": "kms:CreateGrant",
        "Conditional": true,
        "Condition": "use_kms"
      },
      {
        "Action": "backup:CreateBackupVault",
        "Conditional": true,
        "Condition": "use_kms"
      }
    ]
  }
}`

func TestParseResourceFileStructured_MatchesPreRefactorWalker(t *testing.T) {
	var want map[string]map[string][]ExtractedAction
	if err := json.Unmarshal([]byte(legacyGoldens), &want); err != nil {
		t.Fatalf("parse legacyGoldens: %v", err)
	}

	for name, src := range fixtures {
		t.Run(name, func(t *testing.T) {
			got, err := ParseResourceFileStructured(src, "aws_backup_vault", "X")
			if err != nil {
				t.Fatalf("ParseResourceFileStructured failed: %v", err)
			}
			// legacyGoldens holds the pre-refactor output exactly as captured
			// from main, so it carries only the fields that walker produced.
			// ConditionKind is this branch's addition and is asserted separately
			// below rather than written into the golden: editing the golden to
			// include a field the old walker never emitted would make the test
			// assert itself instead of the old behaviour.
			gotLegacy, wantLegacy := legacyShape(got), legacyShape(want[name])
			if !reflect.DeepEqual(gotLegacy, wantLegacy) {
				t.Errorf("merged traversal diverges from the pre-refactor walker\n got: %s\nwant: %s",
					formatActionMap(gotLegacy), formatActionMap(wantLegacy))
			}

			// Every fixture here gates on d.GetOk or d.Get, so each gated call
			// must carry the presence kind.
			for _, actions := range got {
				for _, a := range actions {
					if a.Conditional && a.ConditionKind != ConditionPresence {
						t.Errorf("%s: ConditionKind = %q, want %q", a.Action, a.ConditionKind, ConditionPresence)
					}
				}
			}
		})
	}
}

func formatActionMap(m map[string][]ExtractedAction) string {
	var b strings.Builder
	for op, actions := range m {
		for _, a := range actions {
			fmt.Fprintf(&b, "%s: %s (cond=%t reason=%q)\n", op, a.Action, a.Conditional, a.Condition)
		}
	}
	return b.String()
}

// legacyShape clears the fields this branch added, so the pre-refactor golden
// can stay byte-for-byte as it was captured from main.
func legacyShape(m map[string][]ExtractedAction) map[string][]ExtractedAction {
	out := make(map[string][]ExtractedAction, len(m))
	for op, actions := range m {
		stripped := make([]ExtractedAction, 0, len(actions))
		for _, a := range actions {
			a.ConditionKind = ""
			a.BestEffort = false
			stripped = append(stripped, a)
		}
		out[op] = stripped
	}
	return out
}
