package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

type Config struct {
	DbPath          string
	SignatureSecret string
}

type App struct {
	Db     *sqlx.DB
	Router *mux.Router
}

func NewApp(l *log.Logger, cfg Config) *App {
	db := initSqliteDb(cfg.DbPath)
	repo := NewRepo(l, db)
	signer := NewSigner(cfg.SignatureSecret)
	handler := NewHandler(l, repo, signer)
	router := setupRouter(handler)

	return &App{db, router}
}

func setupRouter(h *Handler) *mux.Router {
	router := mux.NewRouter()
	post := router.Methods(http.MethodPost, http.MethodOptions).Subrouter()

	post.HandleFunc("/answer", h.SignAnswer)
	post.HandleFunc("/signature/verify", h.VerifySignature)

	return router
}

func initSqliteDb(path string) *sqlx.DB {
	db, err := sqlx.Connect("sqlite3", path)
	if err != nil {
		log.Fatal(err)
	}

	initSql := `
		CREATE TABLE IF NOT EXISTS signatures (
			id INTEGER PRIMARY KEY AUTOINCREMENT,	
			user_id STRING NOT NULL,
			hash STRING NOT NULL,
			timestamp STRING NOT NULL,
			answers STRING NOT NULL
		);
		`

	_, err = db.Exec(initSql)
	if err != nil {
		log.Fatal("Failed to initialize db", err)
	}

	return db
}
