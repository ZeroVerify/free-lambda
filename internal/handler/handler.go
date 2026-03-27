package handler

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	bitIndicesTable = "bit_indices"
	statusRevoked   = "REVOKED"
	statusFree      = "FREE"
	statusClaimed   = "CLAIMED"
	maxRetries      = 3
)

type dynamoDBClient interface {
	UpdateItem(ctx context.Context, input *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

var ddbClient dynamoDBClient

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("failed to load AWS config: %v", err)
	}
	ddbClient = dynamodb.NewFromConfig(cfg)
}

func Handle(ctx context.Context, event events.DynamoDBEvent) error {
	for _, record := range event.Records {
		if err := processRecord(ctx, record); err != nil {
			log.Printf("error processing record: %v", err)
		}
	}
	return nil
}
// processRecord — move UserIdentity to record level
func processRecord(ctx context.Context, record events.DynamoDBEventRecord) error {
	switch {
	case record.EventName == "MODIFY":
		return handleRevocation(ctx, record)

	case record.EventName == "REMOVE" &&
		record.UserIdentity != nil &&
		record.UserIdentity.PrincipalID == "dynamodb.amazonaws.com":
		return handleTTLExpiry(ctx, record)

	default:
		return nil
	}
}


func handleRevocation(ctx context.Context, record events.DynamoDBEventRecord) error {
	index, ok := record.Change.NewImage["revocation_index"]
	if !ok {
		log.Printf("SKIP: MODIFY record missing revocation_index, eventID=%s", record.EventID)
		return nil
	}
	current := statusClaimed
	return updateBitWithBackoff(ctx, index.Number(), statusRevoked, &current)
}

func handleTTLExpiry(ctx context.Context, record events.DynamoDBEventRecord) error {
	index, ok := record.Change.OldImage["revocation_index"]
	if !ok {
		log.Printf("SKIP: REMOVE record missing revocation_index, eventID=%s", record.EventID)
		return nil
	}
	return updateBitWithBackoff(ctx, index.Number(), statusFree, nil)
}

func updateBitWithBackoff(ctx context.Context, revocationIndex string, targetStatus string, requiredCurrentStatus *string) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(bitIndicesTable),
		Key: map[string]types.AttributeValue{
			"revocation_index": &types.AttributeValueMemberN{Value: revocationIndex},
		},
		UpdateExpression: aws.String("SET #s = :target"),
		ExpressionAttributeNames: map[string]string{
			"#s": "status",
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":target": &types.AttributeValueMemberS{Value: targetStatus},
		},
	}

	if requiredCurrentStatus != nil {
		input.ConditionExpression = aws.String("#s = :current")
		input.ExpressionAttributeValues[":current"] = &types.AttributeValueMemberS{
			Value: *requiredCurrentStatus,
		}
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<attempt) * 100 * time.Millisecond
			time.Sleep(backoff)
		}

		_, err := ddbClient.UpdateItem(ctx, input)
		if err == nil {
			return nil
		}

		if isTransient(err) {
			lastErr = err
			log.Printf("transient error on attempt %d: %v", attempt+1, err)
			continue
		}

		log.Printf("SKIP: non-transient DynamoDB error for index=%s: %v", revocationIndex, err)
		return nil
	}

	return fmt.Errorf("exhausted retries for index=%s: %w", revocationIndex, lastErr)
}

func isTransient(err error) bool {
	switch err.(type) {
	case *types.ProvisionedThroughputExceededException,
		*types.RequestLimitExceeded,
		*types.InternalServerError:
		return true
	}
	return false
}