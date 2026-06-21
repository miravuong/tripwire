package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"main/alerting"
	"main/internal/server"
	"main/rotation"
	"main/rotation/providers/noop"
)

const (
	modeServe  = "serve"
	modeRotate = "rotate"

	defaultScheduledRepository = "scheduled-rotation"
	defaultScheduledBranch     = "scheduled"
	defaultScheduledCommitSHA  = "cron"
	defaultScheduledRule       = "scheduled-rotation"
	defaultScheduledSource     = "cron"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatalf("tripwire failed: %v", err)
	}
}

func run(ctx context.Context, args []string) error {
	mode, err := parseMode(args)
	if err != nil {
		return err
	}

	switch mode {
	case modeServe:
		return runServer(ctx)
	case modeRotate:
		return runScheduledRotation(ctx)
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}
}

func parseMode(args []string) (string, error) {
	if len(args) > 0 {
		switch args[0] {
		case modeServe, modeRotate:
			if len(args) > 1 {
				return "", fmt.Errorf("%s mode does not accept arguments", args[0])
			}
			return args[0], nil
		}
	}

	flags := flag.NewFlagSet("tripwire", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	mode := flags.String("mode", modeServe, "execution mode: serve or rotate")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	if flags.NArg() > 0 {
		return "", fmt.Errorf("unsupported command %q", flags.Arg(0))
	}
	if *mode != modeServe && *mode != modeRotate {
		return "", fmt.Errorf("unsupported mode %q", *mode)
	}
	return *mode, nil
}

func runServer(ctx context.Context) error {
	log.Println("tripwire starting")

	config, err := server.LoadConfigFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	sender := alerting.NewSender(httpClient)
	rotationSvc := rotation.NewService(noop.NewProvider())

	handler, err := server.NewHandler(server.Dependencies{
		Config:   config,
		Sender:   sender,
		Rotation: rotationSvc,
		Logger:   log.Default(),
	})
	if err != nil {
		return fmt.Errorf("build handler: %w", err)
	}

	srv := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)

	go func() {
		log.Printf("listening on %s", config.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	log.Println("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}

	log.Println("tripwire stopped")
	return nil
}

func runScheduledRotation(ctx context.Context) error {
	if !rotationEnabled() {
		log.Println("scheduled rotation disabled")
		return nil
	}

	rotationSvc := rotation.NewService(noop.NewProvider())
	results, err := rotationSvc.RotateAll(ctx, scheduledRotationEvent(time.Now().UTC()))
	if err != nil {
		return fmt.Errorf("scheduled rotation: %w", err)
	}

	log.Printf("scheduled rotation completed: rotations_count=%d", len(results))
	for _, result := range results {
		log.Printf("rotation result: provider=%s status=%s credential_id=%s message=%s",
			result.Provider,
			result.Status,
			result.CredentialID,
			result.Message,
		)
	}
	return nil
}

func rotationEnabled() bool {
	value := os.Getenv("ROTATION_ENABLED")
	if value == "" {
		return true
	}
	switch value {
	case "1", "true", "TRUE", "True", "yes", "YES", "Yes":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "No":
		return false
	default:
		return true
	}
}

func scheduledRotationEvent(detectedAt time.Time) rotation.DetectionEvent {
	return rotation.DetectionEvent{
		Repository: getenvDefault("ROTATION_REPOSITORY", defaultScheduledRepository),
		Branch:     getenvDefault("ROTATION_BRANCH", defaultScheduledBranch),
		CommitSHA:  getenvDefault("ROTATION_COMMIT_SHA", defaultScheduledCommitSHA),
		Rule:       getenvDefault("ROTATION_RULE", defaultScheduledRule),
		Source:     getenvDefault("ROTATION_SOURCE", defaultScheduledSource),
		DetectedAt: detectedAt,
	}
}

func getenvDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
