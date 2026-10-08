// A trimmed copy of a terraform-provider-aws resource file. It gives the
// check tests real provider-source parser output without the provider clone.

package backup

import (
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
)

// @SDKResource("aws_backup_vault", name="Vault")
// @Tags(identifierAttribute="arn")
func resourceVaultCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.CreateBackupVault(ctx, &backup.CreateBackupVaultInput{})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating Backup Vault: %s", err)
	}

	if _, ok := d.GetOk("kms_key_arn"); ok {
		kmsConn := meta.(*conns.AWSClient).KMSClient(ctx)
		_, err := kmsConn.CreateGrant(ctx, &kms.CreateGrantInput{})
		if err != nil {
			return sdkdiag.AppendErrorf(diags, "creating KMS grant: %s", err)
		}
	}

	return append(diags, resourceVaultRead(ctx, d, meta)...)
}

func resourceVaultRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading Backup Vault: %s", err)
	}
	return diags
}

func resourceVaultDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).BackupClient(ctx)
	_, err := conn.DeleteBackupVault(ctx, &backup.DeleteBackupVaultInput{})
	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting Backup Vault: %s", err)
	}
	return diags
}
