package github

import (
	"fmt"
	"time"
	httpclient "vuln-scan-api/internal/http_client"
)

type RawFileContent []struct {
	ScanResults struct {
		ScanID          string    `json:"scan_id"`
		Timestamp       time.Time `json:"timestamp"`
		ScanStatus      string    `json:"scan_status"`
		ResourceType    string    `json:"resource_type"`
		ResourceName    string    `json:"resource_name"`
		Vulnerabilities []struct {
			ID             string    `json:"id"`
			Severity       string    `json:"severity"`
			Cvss           float64   `json:"cvss"`
			Status         string    `json:"status"`
			PackageName    string    `json:"package_name"`
			CurrentVersion string    `json:"current_version"`
			FixedVersion   string    `json:"fixed_version"`
			Description    string    `json:"description"`
			PublishedDate  time.Time `json:"published_date"`
			Link           string    `json:"link"`
			RiskFactors    []string  `json:"risk_factors"`
		} `json:"vulnerabilities"`
		Summary struct {
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

func addToDatabase(resp RawFileContent) error {
	return nil
}

func getFileAndAddToDB(root string, file string) {
	_, err := getFileContent(root, file)
	if err != nil {
		fmt.Println("Error getting file content", err)
		return
	}
}

func GetAllFiles(root string, files []string) {
	for _, file := range files {
		go getFileContent(root, file)
	}
}
