package github

import (
	"testing"
)

func TestGetFileContentValid(t *testing.T) {
	resp, err := GetFileContent("velancio/vulnerability_scans", "vulnscan15.json")
	if err != nil {
		t.Fatalf("Error fetching from github, expected nil got %v", err)
	}

	if resp == nil {
		t.Fatalf("Error fetching from github, expected resp got nil")
	}

	if len(*resp) == 0 {
		t.Fatalf("Error fetching from github, got empty response")
	}
}

func TestGetFileContentInValid(t *testing.T) {
	resp, err := GetFileContent("velancio/vulnerability_scans", "invalid")
	if err == nil {
		t.Fatalf("Error fetching from github, expected err got nil")
	}

	if resp != nil {
		t.Fatalf("Error fetching from github, expected nil got %v", resp)
	}
}
