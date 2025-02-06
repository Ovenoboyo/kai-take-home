package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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

func (s *ScanArgs) RunScan() error {
	fmt.Println(s)
	if err := s.SanitizeRepo(); err != nil {
		return err
	}

	github.GetAllFiles(s.Repo, s.Files)
	return nil
}
