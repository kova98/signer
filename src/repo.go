package main

import (
	"log"

	"github.com/jmoiron/sqlx"
)

type Repo struct {
	l  *log.Logger
	db *sqlx.DB
}

func NewRepo(l *log.Logger, db *sqlx.DB) *Repo {
	return &Repo{l, db}
}

func (repo *Repo) CreateSignature(sign *Signature) error {
	_, err := repo.db.NamedExec(`INSERT INTO signatures (user_id, hash, timestamp, answers) 
								 VALUES (:user_id, :hash, :timestamp, :answers)`, sign)
	return err
}

func (repo *Repo) GetSignaturesByUserId(userId string) ([]Signature, error) {
	signature := []Signature{}
	err := repo.db.Select(&signature, "SELECT * FROM signatures WHERE user_id = $1", userId)
	return signature, err
}
