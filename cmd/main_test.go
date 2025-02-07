package main

import (
	"bytes"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
	"vuln-scan-api/internal/commands"
	"vuln-scan-api/internal/database"

	"github.com/valyala/fasthttp"
)

var server *fasthttp.Server
var serverLock sync.Mutex = sync.Mutex{}

func startTestServer() {
	serverLock.Lock()
	defer serverLock.Unlock()

	database.Initialize()
	server = StartServer()
	time.Sleep(1000 * time.Millisecond)
}

func stopTestServer() {
	serverLock.Lock()
	defer serverLock.Unlock()

	if server != nil {
		server.Shutdown()
		server = nil
	}
	database.DeleteDb()

	commands.WaitForScan()
	time.Sleep(1000 * time.Millisecond)
}

func TestMain(m *testing.M) {
	startTestServer()

	code := m.Run() // Run all tests

	stopTestServer()

	os.Exit(code)
}

func TestInvalidMethod(t *testing.T) {

	resp, err := http.Get("http://localhost:8080/scan")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestInvalidPath(t *testing.T) {

	resp, err := http.Post("http://localhost:8080/invalid", "application/json", nil)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestScanValid(t *testing.T) {

	resp, err := http.Post("http://localhost:8080/scan", "application/json", bytes.NewBuffer([]byte(`{
	    "repo": "https://github.com/velancio/vulnerability_scans",
	    "files": [
	        "vulnscan15.json",
	        "vulnscan16.json"
	    ]
	}`)))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 500 {
		t.Errorf("expected status 200 or 500, got %d", resp.StatusCode)
	}
}

func TestQueryValid(t *testing.T) {

	resp, err := http.Post("http://localhost:8080/query", "application/json", bytes.NewBuffer([]byte(`{"filters": {"severity": "HIGH"}}`)))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 500 {
		t.Errorf("expected status 200 or 500, got %d", resp.StatusCode)
	}
}

func TestScanInvalidBody(t *testing.T) {

	resp, err := http.Post("http://localhost:8080/scan", "application/json", bytes.NewBuffer([]byte(`invalid json`)))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}

func TestQueryInvalidBody(t *testing.T) {

	resp, err := http.Post("http://localhost:8080/query", "application/json", bytes.NewBuffer([]byte(`invalid json`)))
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}
}
