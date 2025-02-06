package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"vuln-scan-api/internal/database"
	"vuln-scan-api/internal/github"
)

type ScanArgs struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

func NewScanArgs(data []byte) (*ScanArgs, error) {
	var args ScanArgs
	err := json.Unmarshal(data, &args)
	if err != nil {
		return nil, err
	}

	return &args, nil
}

func (s *ScanArgs) SanitizeRepo() error {
	parsedURL, err := url.Parse(s.Repo)
	if err != nil {
		return err
	}

	s.Repo = strings.Trim(parsedURL.Path, "/")
	return nil
}

func addVulnToDB(resp *github.RawFileContent, file string) {
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

func (s *ScanArgs) RunScan() error {
	if err := s.SanitizeRepo(); err != nil {
		return err
	}

	for _, file := range s.Files {
		go func() {
			resp, err := github.GetFileContent(s.Repo, file)
			if err != nil {
				fmt.Println(err)
			}
			addVulnToDB(resp, file)
		}()
	}
	return nil
}
