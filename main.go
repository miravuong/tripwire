package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"main/alerting"
	"main/rotation"
	"main/rotation/providers/noop"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("tripwire starting")

	// --- Alerting ---
	httpClient := &http.Client{Timeout: 10 * time.Second}
	sender := alerting.NewSender(httpClient)
	rotationSvc := rotation.NewService(noop.NewProvider())

	// --- HTTP server for health checks and incoming webhook events ---
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	// Receive secret-detection events from CI and dispatch alerts + rotation.
	mux.HandleFunc("/webhook/detection", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		event, err := decodeDetectionEvent(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		results, err := rotationSvc.RotateAll(r.Context(), event)
		if err != nil {
			log.Printf("rotation failed: %v", err)
			http.Error(w, "rotation failed", http.StatusInternalServerError)
			return
		}

		alertEvent := alerting.Event{
			Repository: event.Repository,
			Branch:     event.Branch,
			CommitSHA:  event.CommitSHA,
			Rule:       fallback(event.Rule, "unknown"),
			FilePath:   fallback(event.FilePath, "unknown"),
			Author:     fallback(event.Author, "unknown"),
			DetectedAt: event.DetectedAt,
		}

		if discordURL := strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL")); discordURL != "" {
			if err := sender.SendDiscord(r.Context(), discordURL, alertEvent); err != nil {
				log.Printf("discord alert dispatch failed: %v", err)
				http.Error(w, "discord alert dispatch failed", http.StatusInternalServerError)
				return
			}
		}

		if webhookURL := strings.TrimSpace(os.Getenv("ALERT_WEBHOOK_URL")); webhookURL != "" {
			if err := sender.SendWebhook(r.Context(), webhookURL, alertEvent); err != nil {
				log.Printf("generic webhook dispatch failed: %v", err)
				http.Error(w, "webhook alert dispatch failed", http.StatusInternalServerError)
				return
			}
		}

		response := map[string]any{
			"status":           "accepted",
			"rotations_count":  len(results),
			"rotation_results": results,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("encode response failed: %v", err)
			return
		}
	})

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in background.
	go func() {
		log.Printf("listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Block until shutdown signal.
	<-ctx.Done()
	log.Println("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}

	log.Println("tripwire stopped")
}

func decodeDetectionEvent(r *http.Request) (rotation.DetectionEvent, error) {
	event := rotation.DetectionEvent{
		Repository: strings.TrimSpace(r.Header.Get("X-Repository")),
		Branch:     strings.TrimSpace(r.Header.Get("X-Branch")),
		CommitSHA:  strings.TrimSpace(r.Header.Get("X-Commit-SHA")),
		Rule:       strings.TrimSpace(r.Header.Get("X-Rule")),
		FilePath:   strings.TrimSpace(r.Header.Get("X-File-Path")),
		Author:     strings.TrimSpace(r.Header.Get("X-Author")),
		Source:     "http-header",
		DetectedAt: time.Now().UTC(),
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return rotation.DetectionEvent{}, fmt.Errorf("read request body: %w", err)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		if err := event.Validate(); err != nil {
			return rotation.DetectionEvent{}, fmt.Errorf("invalid detection event: %w", err)
		}
		return event, nil
	}

	var payload rotation.DetectionEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return rotation.DetectionEvent{}, fmt.Errorf("invalid JSON payload: %w", err)
	}

	payload.Repository = fallback(payload.Repository, event.Repository)
	payload.Branch = fallback(payload.Branch, event.Branch)
	payload.CommitSHA = fallback(payload.CommitSHA, event.CommitSHA)
	payload.Rule = fallback(payload.Rule, event.Rule)
	payload.FilePath = fallback(payload.FilePath, event.FilePath)
	payload.Author = fallback(payload.Author, event.Author)
	payload.Source = fallback(payload.Source, "github-actions")
	if payload.DetectedAt.IsZero() {
		payload.DetectedAt = time.Now().UTC()
	}

	if err := payload.Validate(); err != nil {
		return rotation.DetectionEvent{}, fmt.Errorf("invalid detection event: %w", err)
	}
	return payload, nil
}

func fallback(primary, secondary string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	return strings.TrimSpace(secondary)
}
