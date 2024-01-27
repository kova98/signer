package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type Handler struct {
	l      *log.Logger
	repo   *Repo
	signer *Signer
}

func NewHandler(l *log.Logger, repo *Repo, signer *Signer) *Handler {
	return &Handler{l, repo, signer}
}

func (h *Handler) SignAnswer(w http.ResponseWriter, r *http.Request) {
	h.l.Println("Handle POST answer")

	var req SignAnswerRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		HttpError(w, "Invalid request.", http.StatusBadRequest)
		return
	}

	if req.Jwt == "" {
		HttpError(w, "Field 'jwt' is required.", http.StatusBadRequest)
		return
	}

	if len(req.Answers) == 0 {
		HttpError(w, "Field 'answers' is required.", http.StatusBadRequest)
		return
	}

	answer := Answer{
		Jwt:     req.Jwt,
		Answers: req.Answers,
	}
	hash, err := h.signer.Sign(answer)
	if err != nil {
		h.l.Println("Unable to sign answer:", err)
		HttpError(w, "Unexpected error.", http.StatusInternalServerError)
		return
	}

	userId, err := h.signer.ParseSubClaimFromJwt(req.Jwt)
	if err != nil {
		HttpError(w, "Missing sub claim in JWT.", http.StatusBadRequest)
		return
	}

	answersJson, err := json.Marshal(req.Answers)
	if err != nil {
		h.l.Println("Unable to marshal answers:", err)
		HttpError(w, "Unexpected error.", http.StatusInternalServerError)
		return
	}

	sign := &Signature{
		UserId:    userId,
		Hash:      hash,
		Answers:   string(answersJson),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	err = h.repo.CreateSignature(sign)
	if err != nil {
		h.l.Println("Unable to create signature:", err)
		HttpError(w, "Unexpected error.", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(SignAnswerResponse{hash})
	if err != nil {
		HttpError(w, "Unable to encode questions", http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) VerifySignature(w http.ResponseWriter, r *http.Request) {
	h.l.Println("Handle POST signature/verify")

	var req VerifySignatureRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		HttpError(w, "Invalid request.", http.StatusBadRequest)
		return
	}

	if req.UserId == "" {
		HttpError(w, "Field 'user_id' is required.", http.StatusBadRequest)
		return
	}

	if req.Signature == "" {
		HttpError(w, "Field 'signature' is required.", http.StatusBadRequest)
		return
	}

	signatures, err := h.repo.GetSignaturesByUserId(req.UserId)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			HttpError(w, "Signature does not belong to the user.", http.StatusUnauthorized)
			return
		}
		h.l.Println("Unable to get signature:", err)
		HttpError(w, "Unexpected error.", http.StatusInternalServerError)
		return
	}

	signature := Signature{}
	signatureFound := false
	for _, sig := range signatures {
		if sig.Hash == req.Signature {
			signature = sig
			signatureFound = true
			break
		}
	}

	if !signatureFound {
		HttpError(w, "Signature does not belong to the user.", http.StatusUnauthorized)
		return
	}

	answers := make(map[string]string)
	err = json.Unmarshal([]byte(signature.Answers), &answers)
	if err != nil {
		h.l.Println("Unable to unmarshal answers:", err)
		HttpError(w, "Unexpected error.", http.StatusInternalServerError)
		return
	}

	response := VerifySignatureResponse{
		Answers:   answers,
		Timestamp: signature.Timestamp,
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		HttpError(w, "Unable to encode questions", http.StatusInternalServerError)
	}
}

func HttpError(w http.ResponseWriter, message string, code int) {
	msg := map[string]string{"error": message}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(msg)
}
