package commands

import (
	"testing"
	"vuln-scan-api/internal/database"
)

func TestScan(t *testing.T) {
	database.Initialize()
	defer database.DeleteDb()

	query, err := NewScanArgs([]byte(`
		{
		    "repo": "https://github.com/velancio/vulnerability_scans",
		    "files": [
		        "vulnscan15.json",
		        "vulnscan16.json"
		    ]
		}
		`))

	if err != nil {
		t.Fatalf("Expected err nil, got %v", err)
	}

	_, err = query.RunScan()

	if err != nil {
		t.Fatalf("Expected err nil, got %v", err)
	}

	WaitForScan()
}

// func TestAddVulns(t *testing.T) {
// 	vulns, err := GetF
// 	fmt.Println()
// }
