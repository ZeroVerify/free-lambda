package main

import (
	"log"

	"github.com/ZeroVerify/free-lambda/internal/handler"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	h, err := handler.New()
	if err != nil {
		log.Fatalf("failed to init handler: %v", err)
	}
	lambda.Start(h.Handle)
}