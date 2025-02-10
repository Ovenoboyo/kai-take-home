package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"vuln-scan-api/internal/database"
	"vuln-scan-api/internal/github"
	"vuln-scan-api/internal/logger"
)

var (
	// True if a scan is already running. False otherwise
	isScanRunning bool = false

	// Lock when isScanRunning is to be accessed
	scanRunningLock sync.RWMutex = sync.RWMutex{}
)

// QueryArgs parses the POST body from /scan
type ScanArgs struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

// NewScanArgs creates a new ScanArgs instance from JSON data
// data: JSON byte array containing the query arguments
// returns: a pointer to ScanArgs and an error if parsing fails
func NewScanArgs(data []byte) (*ScanArgs, error) {
	var args ScanArgs
	err := json.Unmarshal(data, &args)
	if err != nil {
		return nil, err
	}

	return &args, nil
}

// SanitizeRepo sanitizes the repository URL in ScanArgs.
// Returns an error if URL parsing fails.
func (s *ScanArgs) SanitizeRepo() error {
	parsedURL, err := url.Parse(s.Repo)
	if err != nil {
		return err
	}

	s.Repo = strings.Trim(parsedURL.Path, "/")
	return nil
}

// addVulnToDB adds vulnerabilities to the database.
// resp: the raw file content from GitHub.
// file: the file name.
// Returns an error if database operations fail.
func addVulnToDB(resp *github.RawFileContent, file string) error {
	conn := database.NewConn()
	tx, err := conn.GetTx()
	if err != nil {
		return err
	}
	for _, res := range *resp {
		err := conn.AddVulnsToDb(tx, res.ScanResults.Vulnerabilities, file, res.ScanResults.Timestamp)
		if err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// isScanRunning checks if a scan is currently running.
// Returns true if a scan is running, false otherwise.
func (s *ScanArgs) isScanRunning() bool {
	scanRunningLock.RLock()
	defer scanRunningLock.RUnlock()

	return isScanRunning
}

// startScanIfNotRunning runs the vulnerability scan and updates the database.
// Returns a boolean indicating if the scan started and an error if any.
func (s *ScanArgs) startScanIfNotRunning() (bool, error) {
	if s.isScanRunning() {
		return false, nil
	}

	scanRunningLock.Lock()
	defer scanRunningLock.Unlock()

	isScanRunning = true

	if err := s.SanitizeRepo(); err != nil {
		return false, err
	}

	var wg sync.WaitGroup
	for _, file := range s.Files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()

			resp, err := github.GetFileContent(s.Repo, file)
			if err != nil {
				logger.Logger.Error("Failed to get data from github", "err", err)
			}
			if err = addVulnToDB(resp, file); err != nil {
				logger.Logger.Warn("Failed to add vulns to DB", "err", err)
			}
		}(file)
	}

	go func() {
		wg.Wait()
		scanRunningLock.Lock()
		defer scanRunningLock.Unlock()

		isScanRunning = false
	}()
	return true, nil
}

// RunScan runs the scan in background and returns a sanitized response / error message
// The response should be sanitized to avoid leaking internal errors
func (s *ScanArgs) RunScan() ([]byte, error) {
	success, err := s.startScanIfNotRunning()
	if err != nil {
		return nil, fmt.Errorf("Failed to start scan")
	}

	if !success {
		return nil, fmt.Errorf("Scan is already running")
	}

	return []byte("success"), nil
}

// WaitForScan waits for the current scan to complete.
// Only used in tests
func WaitForScan() {
	for {
		scanRunningLock.RLock()
		if !isScanRunning {
			scanRunningLock.RUnlock()
			break
		}
		scanRunningLock.RUnlock()
	}
}
