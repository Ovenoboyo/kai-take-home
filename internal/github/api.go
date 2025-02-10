package github

import (
	"fmt"
	"time"
	"vuln-scan-api/internal/database"
	"vuln-scan-api/internal/httpclient"
	"vuln-scan-api/internal/logger"
)

// RawFileContent represents the structure of JSON file to be scanned
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

// GetFileContent fetches the content of a file from a GitHub repository
// root: the root path of the GitHub repository
// file: the file path within the repository
// returns: a pointer to RawFileContent and an error if fetching fails
func GetFileContent(root string, file string) (*RawFileContent, error) {
	client := httpclient.NewClient[RawFileContent]()

	retry := 0
	for {
		resp, err := client.Get(fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s", root, file))
		if err != nil {
			logger.Logger.Error("Failed to fetch from github, ", "err", err)
			retry += 1
			if retry <= 2 {
				continue
			} else {
				return nil, err
			}
		}
		return resp, nil
	}
}
