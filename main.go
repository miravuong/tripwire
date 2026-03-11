package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"main/alerting"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("tripwire starting")

	// --- Alerting ---
	httpClient := &http.Client{Timeout: 10 * time.Second}
	sender := alerting.NewSender(httpClient)

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

		// TODO: parse incoming detection event from CI payload
		// TODO: trigger credential rotation via rotation service
		// TODO: dispatch alert to configured channels

		discordURL := os.Getenv("DISCORD_WEBHOOK_URL")
		if discordURL == "" {
			http.Error(w, "DISCORD_WEBHOOK_URL not configured", http.StatusInternalServerError)
			return
		}

		event := alerting.Event{
			Repository: r.Header.Get("X-Repository"),
			Branch:     r.Header.Get("X-Branch"),
			CommitSHA:  r.Header.Get("X-Commit-SHA"),
			Rule:       r.Header.Get("X-Rule"),
			FilePath:   r.Header.Get("X-File-Path"),
			Author:     r.Header.Get("X-Author"),
			DetectedAt: time.Now().UTC(),
		}

		if err := sender.SendDiscord(r.Context(), discordURL, event); err != nil {
			log.Printf("alert dispatch failed: %v", err)
			http.Error(w, "alert dispatch failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintln(w, "event received")
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
