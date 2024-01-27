# Test Signer API

The Test Signer API allows clients to signing answers and verifying the signatures of the answers.

For persistence, it uses an **Sqlite** database.

## Running The Tests

To run the tests, open the _src_ directory and run `go test`

## Running The Server

To run the server, open to the _src_ directory and run `go run .`

The default port is 3000. Set env variable `PORT` to override.

## Endpoints

### Sign Answer

`POST /answer`

```json
{
  "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LWlkIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.wDEN_8kZ4w6O9yx0t8xGCIETyyhIS6suwZK0NaPXU2Q",
  "answers": {
    "question": "answer"
  }
}
```

### Verify Signature

`POST /signature/verify`

```json
{
  "user_id": "test-id",
  "signature": "9278da988340ce06e285b894c353fc83203016e344e1dc87eafbb029ef8e8652"
}
```
