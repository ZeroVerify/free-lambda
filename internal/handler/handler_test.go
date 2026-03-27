package handler

import (
	"context"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type mockDDB struct {
	called    bool
	lastInput *dynamodb.UpdateItemInput
	returnErr error
}

func (m *mockDDB) UpdateItem(ctx context.Context, input *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	m.called = true
	m.lastInput = input
	return &dynamodb.UpdateItemOutput{}, m.returnErr
}

func TestHandleRevocation(t *testing.T) {
	mock := &mockDDB{}
	ddbClient = mock

	event := events.DynamoDBEvent{
		Records: []events.DynamoDBEventRecord{
			{
				EventID:   "test-1",
				EventName: "MODIFY",
				Change: events.DynamoDBStreamRecord{
					NewImage: map[string]events.DynamoDBAttributeValue{
						"revocation_index": events.NewNumberAttribute("42"),
					},
				},
			},
		},
	}

	err := Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !mock.called {
		t.Fatal("expected UpdateItem to be called")
	}
}

func TestHandleRevocation_MissingIndex(t *testing.T) {
	mock := &mockDDB{}
	ddbClient = mock

	event := events.DynamoDBEvent{
		Records: []events.DynamoDBEventRecord{
			{
				EventID:   "test-2",
				EventName: "MODIFY",
				Change: events.DynamoDBStreamRecord{
					NewImage: map[string]events.DynamoDBAttributeValue{},
				},
			},
		},
	}

	err := Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error on malformed record, got: %v", err)
	}
	if mock.called {
		t.Fatal("expected UpdateItem NOT to be called for malformed record")
	}
}

func TestHandleTTLExpiry(t *testing.T) {
	mock := &mockDDB{}
	ddbClient = mock

	event := events.DynamoDBEvent{
		Records: []events.DynamoDBEventRecord{
			{
				EventID:   "test-3",
				EventName: "REMOVE",
				UserIdentity: &events.DynamoDBUserIdentity{
					PrincipalID: "dynamodb.amazonaws.com",
				},
				Change: events.DynamoDBStreamRecord{
					OldImage: map[string]events.DynamoDBAttributeValue{
						"revocation_index": events.NewNumberAttribute("42"),
					},
				},
			},
		},
	}

	err := Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !mock.called {
		t.Fatal("expected UpdateItem to be called")
	}
}

func TestHandleTTLExpiry_MissingIndex(t *testing.T) {
	mock := &mockDDB{}
	ddbClient = mock

	event := events.DynamoDBEvent{
		Records: []events.DynamoDBEventRecord{
			{
				EventID:   "test-4",
				EventName: "REMOVE",
				UserIdentity: &events.DynamoDBUserIdentity{
					PrincipalID: "dynamodb.amazonaws.com",
				},
				Change: events.DynamoDBStreamRecord{
					OldImage: map[string]events.DynamoDBAttributeValue{},
				},
			},
		},
	}

	err := Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error on malformed record, got: %v", err)
	}
	if mock.called {
		t.Fatal("expected UpdateItem NOT to be called for malformed record")
	}
}

func TestHandleManualDelete_Ignored(t *testing.T) {
	mock := &mockDDB{}
	ddbClient = mock

	event := events.DynamoDBEvent{
		Records: []events.DynamoDBEventRecord{
			{
				EventID:   "test-5",
				EventName: "REMOVE",
				UserIdentity: &events.DynamoDBUserIdentity{
					PrincipalID: "some-admin-user",
				},
				Change: events.DynamoDBStreamRecord{
					OldImage: map[string]events.DynamoDBAttributeValue{
						"revocation_index": events.NewNumberAttribute("42"),
					},
				},
			},
		},
	}

	err := Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if mock.called {
		t.Fatal("expected UpdateItem NOT to be called for manual delete")
	}
}

func TestHandleUnknownEvent_Ignored(t *testing.T) {
	mock := &mockDDB{}
	ddbClient = mock

	event := events.DynamoDBEvent{
		Records: []events.DynamoDBEventRecord{
			{
				EventID:   "test-6",
				EventName: "INSERT",
				Change: events.DynamoDBStreamRecord{
					NewImage: map[string]events.DynamoDBAttributeValue{
						"revocation_index": events.NewNumberAttribute("42"),
					},
				},
			},
		},
	}

	err := Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if mock.called {
		t.Fatal("expected UpdateItem NOT to be called for INSERT event")
	}
}

func TestHandleMultipleRecords(t *testing.T) {
	mock := &mockDDB{}
	ddbClient = mock

	event := events.DynamoDBEvent{
		Records: []events.DynamoDBEventRecord{
			{
				EventID:   "test-7a",
				EventName: "MODIFY",
				Change: events.DynamoDBStreamRecord{
					NewImage: map[string]events.DynamoDBAttributeValue{
						"revocation_index": events.NewNumberAttribute("1"),
					},
				},
			},
			{
				EventID:   "test-7b",
				EventName: "MODIFY",
				Change: events.DynamoDBStreamRecord{
					NewImage: map[string]events.DynamoDBAttributeValue{},
				},
			},
			{
				EventID:   "test-7c",
				EventName: "REMOVE",
				UserIdentity: &events.DynamoDBUserIdentity{
					PrincipalID: "dynamodb.amazonaws.com",
				},
				Change: events.DynamoDBStreamRecord{
					OldImage: map[string]events.DynamoDBAttributeValue{
						"revocation_index": events.NewNumberAttribute("2"),
					},
				},
			},
		},
	}

	err := Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !mock.called {
		t.Fatal("expected UpdateItem to be called at least once")
	}
}