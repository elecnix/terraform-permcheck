// A trimmed copy of a generated tags_gen.go file from terraform-provider-aws.

package backup

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

func listTags(ctx context.Context, conn *backup.Client, identifier string) error {
	_, err := conn.ListTags(ctx, &backup.ListTagsInput{ResourceArn: aws.String(identifier)})
	if err != nil {
		return err
	}
	return nil
}

func updateTags(ctx context.Context, conn *backup.Client, identifier string, oldTagsMap, newTagsMap any) error {
	removedTags := oldTags.Removed(newTags)
	if len(removedTags) > 0 {
		_, err := conn.UntagResource(ctx, &backup.UntagResourceInput{ResourceArn: aws.String(identifier)})
		if err != nil {
			return err
		}
	}
	updatedTags := oldTags.Updated(newTags)
	if len(updatedTags) > 0 {
		_, err := conn.TagResource(ctx, &backup.TagResourceInput{ResourceArn: aws.String(identifier)})
		if err != nil {
			return err
		}
	}
	return nil
}
