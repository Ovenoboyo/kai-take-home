# Take home test - Kai Security

## Description

This project is a single GO service that provides two REST APIs to scan a GitHub repository for JSON files in a specific format and store their contents, and query the stored JSON payloads using key-value filters (only `severity` implemented as of now).

The service creates a sqlite3 database in the same directory as the executable which is responsible for storing the parsed data.

The service implements 2 POST APIs
- `/scan` - Responsible for scanning the provided files in the repo, parsing and storing them in the DB. Scan runs asynchronous. The API will succeed before the scan is complete. Subsequent calls to `/scan` when a scan is already running will fetch an error
- `/query` - Fetches data based on filters. If no filters are passed, all data is returned.

To fetch the data from Github, the service makes a simple GET request to `raw.githubusercontent.com`. If the request fails, the services tries again 2 more times without any interval between retries.

The service is built using the following libraries in GO:
- [fasthttp](https://github.com/valyala/fasthttp)
- [go-sqlite3](https://github.com/mattn/go-sqlite3)

## Requirements

### Problem Statement

Build a single Go service with two REST APIs to:

- Scan the GitHub repository (https://github.com/velancio/vulnerability_scans) for JSON files and store their contents.
- Query stored JSON payloads using key-value filters.

### API Requirements

#### 1. Scan API

**Endpoint:** `POST /scan`

```json
{
  "repo": "<repo root>",
  "files": ["<filename1>", "<filename2>", …]
}
```

- Fetches all .json files from the specified GitHub path.
- Processes files containing arrays of JSON payloads (see example below).
- Stores each payload with metadata (source file, scan time). Feel free to design whatever schemas and data structures are needed.

#### 2. Query API

**Endpoint:** `POST /query`

```json
{
  "filters": {
    "severity": "HIGH"
  }
}
```

- Returns all payloads matching any one filter key (exact matches). Focus on just one filter for the assignment: “severity”.

### Example Response Expected

```json
[
  {
    "id": "CVE-2024-1234",
    "severity": "HIGH",
    "cvss": 8.5,
    "status": "fixed",
    "package_name": "openssl",
    "current_version": "1.1.1t-r0",
    "fixed_version": "1.1.1u-r0",
    "description": "Buffer overflow vulnerability in OpenSSL",
    "published_date": "2024-01-15T00:00:00Z",
    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    "risk_factors": [
      "Remote Code Execution",
      "High CVSS Score",
      "Public Exploit Available"
    ]
  },
  {
    "id": "CVE-2024-8902",
    "severity": "HIGH",
    "cvss": 8.2,
    "status": "fixed",
    "package_name": "openldap",
    "current_version": "2.4.57",
    "fixed_version": "2.4.58",
    "description": "Authentication bypass vulnerability in OpenLDAP",
    "published_date": "2024-01-21T00:00:00Z",
    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-8902",
    "risk_factors": [
      "Authentication Bypass",
      "High CVSS Score"
    ]
  }
  ...
]
```

## Building from source

To build the project from source, run
```bash
make build
```

## Usage

To run the project, simply run
```bash
make run
```

## Running tests

To run the tests, run
```bash
make test
```

This will run the tests and generate a coverage report in /tmp which should be automatically opened in the default browser.

## Running in docker

To build and run a docker container, execute

```bash
make docker-run
```

By default, it should build the container with a take `kai-take-home` and run it export port `80` on the host.

## Documentation

Further documentation can be found in [docs.md](./docs.md)
