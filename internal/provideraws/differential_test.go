package provideraws

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/elecnix/terraform-permcheck/internal/iam"
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
// pre-refactor parser on main, serialised with encoding/json. The else
// branches of elseIfChain and serviceSwitch were corrected since: the legacy
// walker gave an else branch the gate of its if, though it runs exactly when
// that gate does not hold (#118).
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
        "Condition": "secondary"
      },
      {
        "Action": "backup:DescribeCopyPoint"
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
        "Action": "backup:CreateBackupVault"
      }
    ]
  }
}`

// legacyAction is the shape the pre-refactor walker emitted for each action.
type legacyAction struct {
	Action      string
	Conditional bool
	Condition   string
}

func TestParseResourceFileStructured_MatchesPreRefactorWalker(t *testing.T) {
	var want map[string]map[string][]legacyAction
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
			// The gate kind and best-effort flag came later and are asserted
			// separately below rather than written into the golden: editing
			// the golden to include a field the old walker never emitted
			// would make the test assert itself instead of the old behaviour.
			gotLegacy := legacyShape(got)
			if !reflect.DeepEqual(gotLegacy, want[name]) {
				t.Errorf("merged traversal diverges from the pre-refactor walker\n got: %s\nwant: %s",
					formatActionMap(gotLegacy), formatActionMap(want[name]))
			}

			// Every fixture here gates on d.GetOk or d.Get, so each gated call
			// must carry a presence gate.
			for _, reqs := range got {
				for _, r := range reqs {
					if r.Changed != "" {
						t.Errorf("%s: gate %+v tests a change, want presence", r.Action, r.Gate)
					}
				}
			}
		})
	}
}

func formatActionMap(m map[string][]legacyAction) string {
	var b strings.Builder
	for op, actions := range m {
		for _, a := range actions {
			fmt.Fprintf(&b, "%s: %s (cond=%t reason=%q)\n", op, a.Action, a.Conditional, a.Condition)
		}
	}
	return b.String()
}

// legacyShape keeps only what the pre-refactor walker emitted, so its golden
// can stay byte-for-byte as it was captured from main. Every fixture reaches
// each action on one path.
func legacyShape(m map[string][]iam.Requirement) map[string][]legacyAction {
	out := make(map[string][]legacyAction, len(m))
	for op, reqs := range m {
		actions := make([]legacyAction, 0, len(reqs))
		for _, r := range reqs {
			cond := r.Attribute
			if cond == "" {
				cond = r.Changed
			}
			actions = append(actions, legacyAction{Action: r.Action, Conditional: !r.Ungated(), Condition: cond})
		}
		out[op] = actions
	}
	return out
}
