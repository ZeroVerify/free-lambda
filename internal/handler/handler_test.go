package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type mockDDB struct {
	calls     []*dynamodb.UpdateItemInput
	returnErr error
}

func (m *mockDDB) UpdateItem(ctx context.Context, input *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	m.calls = append(m.calls, input)
	return &dynamodb.UpdateItemOutput{}, m.returnErr
}

func str(s string) events.DynamoDBAttributeValue { return events.NewStringAttribute(s) }
func num(n string) events.DynamoDBAttributeValue { return events.NewNumberAttribute(n) }

func revocationRecord(id, index, oldStatus, newStatus string) events.DynamoDBEventRecord {
	newImage := map[string]events.DynamoDBAttributeValue{"status": str(newStatus)}
	if index != "" {
		newImage["revocation_index"] = num(index)
	}
	return events.DynamoDBEventRecord{
		EventID:   id,
		EventName: "MODIFY",
		Change: events.DynamoDBStreamRecord{
			OldImage: map[string]events.DynamoDBAttributeValue{"status": str(oldStatus)},
			NewImage: newImage,
		},
	}
}

func ttlRecord(id, index string, principal string) events.DynamoDBEventRecord {
	old := map[string]events.DynamoDBAttributeValue{}
	if index != "" {
		old["revocation_index"] = num(index)
	}
	rec := events.DynamoDBEventRecord{
		EventID:   id,
		EventName: "REMOVE",
		Change:    events.DynamoDBStreamRecord{OldImage: old},
	}
	if principal != "" {
		rec.UserIdentity = &events.DynamoDBUserIdentity{PrincipalID: principal}
	}
	return rec
}

func handle(t *testing.T, mock *mockDDB, recs ...events.DynamoDBEventRecord) {
	t.Helper()
	h := &Handler{ddb: mock}
	if err := h.Handle(context.Background(), events.DynamoDBEvent{Records: recs}); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func targetStatus(t *testing.T, in *dynamodb.UpdateItemInput) string {
	t.Helper()
	return in.ExpressionAttributeValues[":target"].(*types.AttributeValueMemberS).Value
}

func TestHandleRevocation(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, revocationRecord("t1", "42", statusActive, statusRevoked))
	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 UpdateItem call, got %d", len(mock.calls))
	}
	if got := targetStatus(t, mock.calls[0]); got != statusRevoked {
		t.Fatalf("expected target %s, got %s", statusRevoked, got)
	}
	if mock.calls[0].ConditionExpression == nil {
		t.Fatal("revocation must be conditional on the bit currently being CLAIMED")
	}
}

func TestHandleRevocation_MissingIndex(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, revocationRecord("t2", "", statusActive, statusRevoked))
	if len(mock.calls) != 0 {
		t.Fatal("expected UpdateItem NOT to be called for malformed record")
	}
}

func TestHandleModify_NotARevocationTransition_Ignored(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, revocationRecord("t3", "42", statusActive, statusActive))
	if len(mock.calls) != 0 {
		t.Fatal("expected UpdateItem NOT to be called when status did not become REVOKED")
	}
}

func TestHandleRevocation_MetadataSentinel_Ignored(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, revocationRecord("t4", metadataSentinel, statusActive, statusRevoked))
	if len(mock.calls) != 0 {
		t.Fatal("expected UpdateItem NOT to be called for the metadata sentinel row")
	}
}

func TestHandleTTLExpiry(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, ttlRecord("t5", "42", "dynamodb.amazonaws.com"))
	if len(mock.calls) != 1 {
		t.Fatalf("expected 1 UpdateItem call, got %d", len(mock.calls))
	}
	if got := targetStatus(t, mock.calls[0]); got != statusFree {
		t.Fatalf("expected target %s, got %s", statusFree, got)
	}
}

func TestHandleTTLExpiry_MissingIndex(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, ttlRecord("t6", "", "dynamodb.amazonaws.com"))
	if len(mock.calls) != 0 {
		t.Fatal("expected UpdateItem NOT to be called for malformed record")
	}
}

func TestHandleManualDelete_Ignored(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, ttlRecord("t7", "42", ""), ttlRecord("t8", "42", "arn:aws:iam::1:user/someone"))
	if len(mock.calls) != 0 {
		t.Fatal("expected UpdateItem NOT to be called for manual delete")
	}
}

func TestHandleUnknownEvent_Ignored(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock, events.DynamoDBEventRecord{EventID: "t9", EventName: "INSERT"})
	if len(mock.calls) != 0 {
		t.Fatal("expected UpdateItem NOT to be called for INSERT event")
	}
}

func TestHandleMultipleRecords(t *testing.T) {
	mock := &mockDDB{}
	handle(t, mock,
		revocationRecord("m1", "1", statusActive, statusRevoked),
		revocationRecord("m2", "2", statusActive, statusRevoked),
		ttlRecord("m3", "3", "dynamodb.amazonaws.com"),
	)
	if len(mock.calls) != 3 {
		t.Fatalf("expected 3 UpdateItem calls, got %d", len(mock.calls))
	}
}

func TestHandle_OneFailingRecordDoesNotBlockOthers(t *testing.T) {
	mock := &mockDDB{returnErr: errors.New("boom")}
	handle(t, mock, revocationRecord("f1", "1", statusActive, statusRevoked), ttlRecord("f2", "2", "dynamodb.amazonaws.com"))
	if len(mock.calls) < 2 {
		t.Fatalf("expected both records to be attempted, got %d calls", len(mock.calls))
	}
}
