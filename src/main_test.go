package main

import (
	"log"
	"os"
	"testing"
	"time"

	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

var a *App
var l *log.Logger

func TestMain(m *testing.M) {
	l = log.New(os.Stdout, "signer-test", log.LstdFlags)
	cfg := Config{
		DbPath:          "signer-test.db",
		SignatureSecret: "secret",
	}
	a = NewApp(l, cfg)
	defer a.Db.Close()
	code := m.Run()
	clearTables()
	os.Exit(code)
}

func clearTables() {
	a.Db.Exec("DELETE FROM signatures")
	a.Db.Exec("DELETE FROM sqlite_sequence")
}

// jwt signed with secret "secret" and sub claim "test-id"
const TestJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LWlkIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wDEN_8kZ4w6O9yx0t8xGCIETyyhIS6suwZK0NaPXU2Q"

func TestSignAnswer_InvalidRequest(t *testing.T) {
	clearTables()
	jsonStr := []byte("asdfasdf")
	req, _ := http.NewRequest("POST", "/answer", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusBadRequest, response.Code)
	checkError(t, m, "Invalid request.")
}

func TestSignAnswer_IncompleteRequest(t *testing.T) {
	clearTables()
	var incompleteRequests = []struct {
		req           string
		expectedError string
	}{
		{`{"jwt": "` + TestJwt + `"}`, "Field 'answers' is required."},
		{`{"answers": {"asdf": "asdf"}}`, "Field 'jwt' is required."},
	}
	for _, r := range incompleteRequests {
		l.Println("Testing incomplete request:", r.req)
		jsonStr := []byte(r.req)
		req, _ := http.NewRequest("POST", "/answer", bytes.NewBuffer(jsonStr))

		response := executeRequest(req)
		var m map[string]string
		json.Unmarshal(response.Body.Bytes(), &m)

		checkResponseCode(t, http.StatusBadRequest, response.Code)
		checkError(t, m, r.expectedError)
	}
}

func TestSignAnswer_MissingSubClaim(t *testing.T) {
	clearTables()
	jsonStr := []byte(`{
		"jwt": "invalid jwt",
		"answers": {
			"test": "test"
		}
	}`)
	req, _ := http.NewRequest("POST", "/answer", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusBadRequest, response.Code)
	checkError(t, m, "Missing sub claim in JWT.")
}

func TestSignAnswer_ValidRequest(t *testing.T) {
	clearTables()
	// jwt signed with secret "secret"
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"
	jsonStr := []byte(`{
		"jwt": "` + jwt + `",
		"answers": {
			"test": "test"
		}
	}`)
	req, _ := http.NewRequest("POST", "/answer", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusOK, response.Code)
	if m["test_signature"] == "" {
		t.Errorf("Expected 'test_signature' not to be empty.")
	}
}

func TestVerifySignature_InvalidRequest(t *testing.T) {
	clearTables()
	jsonStr := []byte("asdfsad")
	req, _ := http.NewRequest("POST", "/signature/verify", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusBadRequest, response.Code)
	checkError(t, m, "Invalid request.")
}

func TestVerifySignature_IncompleteRequest(t *testing.T) {
	clearTables()
	var incompleteRequests = []struct {
		req           string
		expectedError string
	}{
		{`{"user_id": "test"}`, "Field 'signature' is required."},
		{`{"signature": "test"}`, "Field 'user_id' is required."},
	}
	for _, r := range incompleteRequests {
		l.Println("Testing incomplete request:", r.req)
		jsonStr := []byte(r.req)
		req, _ := http.NewRequest("POST", "/signature/verify", bytes.NewBuffer(jsonStr))

		response := executeRequest(req)
		var m map[string]string
		json.Unmarshal(response.Body.Bytes(), &m)

		checkResponseCode(t, http.StatusBadRequest, response.Code)
		checkError(t, m, r.expectedError)
	}
}

func TestVerifySignature_UserDoesNotExist(t *testing.T) {
	clearTables()
	jsonStr := []byte(`{
		"user_id": "nonexistant",
		"signature": "test"
	}`)
	req, _ := http.NewRequest("POST", "/signature/verify", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusUnauthorized, response.Code)
	checkError(t, m, "Signature does not belong to the user.")
}

func TestVerifySignature_SignatureDoesNotBelongToUser(t *testing.T) {
	clearTables()
	addSignature(&Signature{
		UserId:    "not test user",
		Hash:      "test",
		Timestamp: "test",
		Answers:   `{"question":"answer"}`,
	})
	jsonStr := []byte(`{
		"user_id": "test user",
		"signature": "test"
	}`)
	req, _ := http.NewRequest("POST", "/signature/verify", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusUnauthorized, response.Code)
	checkError(t, m, "Signature does not belong to the user.")
}

func TestVerifySignature_SignatureDoesNotMatch(t *testing.T) {
	clearTables()
	addSignature(&Signature{
		UserId:    "test user",
		Hash:      "test",
		Timestamp: "test",
		Answers:   `{"question":"answer"}`,
	})
	jsonStr := []byte(`{
		"user_id": "test user",
		"signature": "not test"
	}`)
	req, _ := http.NewRequest("POST", "/signature/verify", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusUnauthorized, response.Code)
	checkError(t, m, "Signature does not belong to the user.")
}

func TestVerifySignature_ValidRequest(t *testing.T) {
	clearTables()
	jsonStr := []byte(`{
		"jwt": "` + TestJwt + `",
		"answers": {
			"question": "answer"
		}
	}`)
	// ensure it works with multiple signatures for the same user
	createSignature(t, jsonStr)
	testSignature := createSignature(t, jsonStr)
	createSignature(t, jsonStr)
	jsonStr = []byte(`{
		"user_id": "test-id",
		"signature": "` + testSignature + `"
	}`)
	req, _ := http.NewRequest("POST", "/signature/verify", bytes.NewBuffer(jsonStr))
	res := executeRequest(req)
	var resModel VerifySignatureResponse
	decodeResponse(t, res, &resModel)

	checkResponseCode(t, http.StatusOK, res.Code)
	if resModel.Answers["question"] != "answer" {
		t.Errorf("Expected answer 'answer'. Got '%s'\n", resModel.Answers["question"])
	}
	timestamp, _ := time.Parse(time.RFC3339, resModel.Timestamp)
	now := time.Now().UTC()
	if now.Sub(timestamp) > time.Second || timestamp.Sub(now) > time.Second {
		t.Errorf("Timestamp %s is not within %s of now %s", timestamp, time.Second, now)
	}
}

func createSignature(t *testing.T, jsonStr []byte) string {
	req, _ := http.NewRequest("POST", "/answer", bytes.NewBuffer(jsonStr))

	response := executeRequest(req)
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)

	checkResponseCode(t, http.StatusOK, response.Code)
	if m["test_signature"] == "" {
		t.Errorf("Expected 'test_signature' not to be empty.")
	}

	return m["test_signature"]
}

func addSignature(s *Signature) {
	_, err := a.Db.NamedExec("INSERT INTO signatures (user_id, hash, timestamp, answers) VALUES (:user_id, :hash, :timestamp, :answers)", s)
	if err != nil {
		l.Fatal("Failed to insert signature:", err)
	}
}

func checkError(t *testing.T, m map[string]string, expected string) {
	if m["error"] != expected {
		t.Errorf("Expected error '%s'. Got '%s'\n", expected, m["error"])
	}
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, v interface{}) {
	err := json.NewDecoder(response.Body).Decode(v)
	if err != nil {
		t.Fatalf("Could not decode response body: %v", err)
	}
}

func executeRequest(req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	a.Router.ServeHTTP(rr, req)

	return rr
}

func checkResponseCode(t *testing.T, expected, actual int) {
	if expected != actual {
		t.Errorf("Expected response code %d. Got %d\n", expected, actual)
	}
}
