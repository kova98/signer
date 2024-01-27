package main

type Signature struct {
	ID        int    `db:"id"`
	UserId    string `db:"user_id"`
	Hash      string `db:"hash"`
	Timestamp string `db:"timestamp"`
	Answers   string `db:"answers"`
}

type Answer struct {
	Jwt     string            `json:"jwt"`
	Answers map[string]string `json:"answers"`
}

type VerifySignatureRequest struct {
	UserId    string `json:"user_id"`
	Signature string `json:"signature"`
}

type VerifySignatureResponse struct {
	Answers   map[string]string `json:"answers"`
	Timestamp string            `json:"timestamp"`
}

type SignAnswerRequest struct {
	Jwt     string            `json:"jwt"`
	Answers map[string]string `json:"answers"`
}

type SignAnswerResponse struct {
	TestSignature string `json:"test_signature"`
}
