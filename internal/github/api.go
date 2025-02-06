package github

import (
	"fmt"
	"time"
	"vuln-scan-api/internal/database"
	"vuln-scan-api/internal/httpclient"
)

type RawFileContent []struct {
	ScanResults struct {
		ScanID          string                     `json:"scan_id"`
		Timestamp       time.Time                  `json:"timestamp"`
		ScanStatus      string                     `json:"scan_status"`
		ResourceType    string                     `json:"resource_type"`
		ResourceName    string                     `json:"resource_name"`
		Vulnerabilities []database.Vulnerabilities `json:"vulnerabilities"`
		Summary         struct {
			TotalVulnerabilities int `json:"total_vulnerabilities"`
			SeverityCounts       struct {
				CRITICAL int `json:"CRITICAL"`
				HIGH     int `json:"HIGH"`
				MEDIUM   int `json:"MEDIUM"`
				LOW      int `json:"LOW"`
			} `json:"severity_counts"`
			FixableCount int  `json:"fixable_count"`
			Compliant    bool `json:"compliant"`
		} `json:"summary"`
		ScanMetadata struct {
			ScannerVersion  string   `json:"scanner_version"`
			PoliciesVersion string   `json:"policies_version"`
			ScanningRules   []string `json:"scanning_rules"`
			ExcludedPaths   []string `json:"excluded_paths"`
		} `json:"scan_metadata"`
	} `json:"scanResults"`
}

func getFileContent(root string, file string) (*RawFileContent, error) {
	client := httpclient.NewClient[RawFileContent]()
	resp, err := client.Get(fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s", root, file))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func getFileAndAddToDB(root string, file string) {
	resp, err := getFileContent(root, file)
	if err != nil {
		fmt.Println("Error getting file content", err)
		return
	}

	conn := database.NewConn()
	tx, err := conn.GetTx()
	if err != nil {
		fmt.Println("Error starting transaction", err)
		return
	}
	for _, res := range *resp {
		err := conn.AddVulnsToDb(tx, res.ScanResults.Vulnerabilities, file, res.ScanResults.Timestamp)
		if err != nil {
			fmt.Println("Error starting transaction", err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		fmt.Println("Error committing transaction", err)
	}
}

func GetAllFiles(root string, files []string) {
	for _, file := range files {
		go getFileAndAddToDB(root, file)
	}
}
