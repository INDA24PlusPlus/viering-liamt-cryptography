# Cryptosak

## Design choices
We chose to use `AES-256-GCM` for encryption and signing, and `argon2` for key derivation. We are lazy so everything upladed to the server is stored in RAM.

## Client
Commands
- `upload <file> <password>`
- `retreive <id> <password> [out]` (optional `out` parameter to specify output file)

## Server
Endpoints
- `POST /file` - Uploads a file (a `EncFile` struct serialized as JSON with serde), returns a `UploadResponse` struct serialized as JSON with serde
- `GET /file/<id>` - Retrieves a file, returns a `RetrieveResponse` struct serialized as JSON with serde