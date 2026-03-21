package handler

import (
	"context"
	"github.com/aws/aws-lambda-go/events"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Handle(ctx context.Context, event events.DynamoDBEvent) error {
	return nil
}