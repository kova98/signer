package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := Config{
		DbPath:          "signer.db",
		SignatureSecret: "secret",
	}
	l := log.New(os.Stdout, "signer", log.LstdFlags)
	app := NewApp(l, cfg)
	defer app.Db.Close()
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	addr := "127.0.0.1:" + port
	s := http.Server{
		Addr:         addr,
		Handler:      app.Router,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	go func() {
		l.Println("Starting server on address " + addr)

		err := s.ListenAndServe()
		if err != nil {
			l.Printf("Error starting server: %s\n", err)
			os.Exit(1)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	sig := <-c
	log.Println("Got signal:", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.Shutdown(ctx)
	cancel()
}
