# MetaMesh Plugin: Full Hash

A MetaMesh plugin that computes SHA-256 hash of the entire file for content identification.

## Description

This plugin computes a full SHA-256 hash of files for content-addressable identification. Unlike the quick CID hash used for file tracking, this provides a complete content hash suitable for:

- Content deduplication
- File integrity verification
- Cross-system file matching

**Note**: This runs on the background queue as hashing large files is I/O intensive.

## Metadata Fields

| Field | Description |
|-------|-------------|
| `cid_sha2-256` | SHA-256 hash in CID format (`sha256-{hash}`) |

## Dependencies

- No plugin dependencies (runs independently)

## Configuration

No configuration required.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/manifest` | GET | Plugin manifest |
| `/configure` | POST | Update configuration |
| `/process` | POST | Process a file |

## Running Locally

```bash
npm install
npm run build
npm start
```

## Docker

```bash
docker build -t metamesh-plugin-fullhash .
docker run -p 8080:8080 metamesh-plugin-fullhash
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP server host |

## License

MIT
