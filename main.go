package main

import (
	"github.com/ZeroVerify/zeroverify-processor/internal/handler"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	h := handler.NewHandler()
	lambda.Start(h.Handle)
}