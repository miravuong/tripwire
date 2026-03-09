package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"main/alerting"
)

func main() {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		log.Fatal("DISCORD_WEBHOOK_URL environment variable is required")
	}

	sender := alerting.NewSender(&http.Client{Timeout: 10 * time.Second})
	event := alerting.Event{
		Repository: "acme/tripwire",
		Branch:     "main",
		CommitSHA:  "abc1234def5678",
		Rule:       "aws-access-key-id",
		FilePath:   "config/settings.py",
		Author:     "dev@example.com",
		DetectedAt: time.Now().UTC(),
	}
	err := sender.SendDiscord(context.Background(), webhookURL, event)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
	} else {
		fmt.Println("OK — message sent to Discord")
	}
}
