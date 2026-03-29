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
	bitIndicesTable  = "zeroverify-bit-indices"
	statusRevoked    = "REVOKED"
	statusFree       = "FREE"
	statusClaimed    = "CLAIMED"
	statusActive     = "ACTIVE"
	maxRetries       = 3
	metadataSentinel = "-1"
)

type dynamoDBClient interface {
	UpdateItem(ctx context.Context, input *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
}

type Handler struct {
	ddb dynamoDBClient
}

func New() (*Handler, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return &Handler{ddb: dynamodb.NewFromConfig(cfg)}, nil
}

func (h *Handler) Handle(ctx context.Context, event events.DynamoDBEvent) error {
	for _, record := range event.Records {
		if err := h.processRecord(ctx, record); err != nil {
			log.Printf("error processing record: %v", err)
		}
	}
	return nil
}

func (h *Handler) processRecord(ctx context.Context, record events.DynamoDBEventRecord) error {
	switch {
	case record.EventName == "MODIFY":
		oldStatus, hasOld := record.Change.OldImage["status"]
		newStatus, hasNew := record.Change.NewImage["status"]
		if !hasOld || !hasNew {
			log.Printf("SKIP: MODIFY missing status in old/new image, eventID=%s", record.EventID)
			return nil
		}
		if oldStatus.String() != statusActive || newStatus.String() != statusRevoked {
			log.Printf("SKIP: MODIFY is not a CLAIMED->REVOKED transition, eventID=%s", record.EventID)
			return nil
		}
		return h.handleRevocation(ctx, record)

	case record.EventName == "REMOVE" &&
		record.UserIdentity != nil &&
		record.UserIdentity.PrincipalID == "dynamodb.amazonaws.com":
		return h.handleTTLExpiry(ctx, record)

	default:
		return nil
	}
}

func (h *Handler) handleRevocation(ctx context.Context, record events.DynamoDBEventRecord) error {
	index, ok := record.Change.NewImage["revocation_index"]
	if !ok {
		log.Printf("SKIP: MODIFY record missing revocation_index, eventID=%s", record.EventID)
		return nil
	}
	if index.Number() == metadataSentinel {
		log.Printf("SKIP: ignoring metadata sentinel row, eventID=%s", record.EventID)
		return nil
	}
	current := statusClaimed
	return h.updateBitWithBackoff(ctx, index.Number(), statusRevoked, &current)
}

func (h *Handler) handleTTLExpiry(ctx context.Context, record events.DynamoDBEventRecord) error {
	index, ok := record.Change.OldImage["revocation_index"]
	if !ok {
		log.Printf("SKIP: REMOVE record missing revocation_index, eventID=%s", record.EventID)
		return nil
	}
	if index.Number() == metadataSentinel {
		log.Printf("SKIP: ignoring metadata sentinel row, eventID=%s", record.EventID)
		return nil
	}
	return h.updateBitWithBackoff(ctx, index.Number(), statusFree, nil)
}

func (h *Handler) updateBitWithBackoff(ctx context.Context, bitIndex string, targetStatus string, requiredCurrentStatus *string) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(bitIndicesTable),
		Key: map[string]types.AttributeValue{
			"bit_index": &types.AttributeValueMemberN{Value: bitIndex},
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

		_, err := h.ddb.UpdateItem(ctx, input)
		if err == nil {
			return nil
		}

		if isTransient(err) {
			lastErr = err
			log.Printf("transient error on attempt %d: %v", attempt+1, err)
			continue
		}

		log.Printf("SKIP: non-transient DynamoDB error for bit_index=%s: %v", bitIndex, err)
		return nil
	}

	return fmt.Errorf("exhausted retries for bit_index=%s: %w", bitIndex, lastErr)
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
