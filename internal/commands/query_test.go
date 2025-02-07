package commands

import (
	"testing"
	"vuln-scan-api/internal/database"
)

func TestGetVulnsBySeverity(t *testing.T) {
	defer database.DeleteDb()

	database.Initialize()
	scan, _ := NewScanArgs([]byte(`
		{
		    "repo": "https://github.com/velancio/vulnerability_scans",
		    "files": [
		        "vulnscan15.json",
		        "vulnscan16.json"
		    ]
		}
		`))

	scan.RunScan()

	WaitForScan()

	query, err := NewQueryArgs([]byte(`{"filters": {"severity": "HIGH"}}`))
	if err != nil {
		t.Fatalf("Expected err nil, got %v", err)
	}

	ret, err := query.GetVulnsBySeverity()

	if err != nil {
		t.Fatalf("Expected err nil, got %v", err)
	}

	if len(ret) == 0 {
		t.Fatalf("Expected non empty response, got empty")
	}
}
