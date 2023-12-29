package utils

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

func AWSClient() *aws.Config {
	profileName, ok := os.LookupEnv("AWS_PROFILE")
	if !ok {
		profileName = "default"
	}
	log.Println("Using AWS profile:", profileName)
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("unable to load AWS configuration, %v", err)
	}
	if cfg.Region == "" {
		log.Fatalf("AWS region is not set")
	}
	log.Println("Using AWS region:", cfg.Region)
	return &cfg
}
