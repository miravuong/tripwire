package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"main/alerting"
	"main/internal/server"
	"main/rotation"
	"main/rotation/providers/noop"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("tripwire starting")

	config, err := server.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
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
		log.Fatalf("build handler: %v", err)
	}

	srv := &http.Server{
		Addr:         config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in background.
	go func() {
		log.Printf("listening on %s", config.ListenAddr)
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
