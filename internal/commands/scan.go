package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"vuln-scan-api/internal/database"
	"vuln-scan-api/internal/github"
)

var (
	isScanRunning   bool         = false
	scanRunningLock sync.RWMutex = sync.RWMutex{}
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

func (s *ScanArgs) isScanRunning() bool {
	scanRunningLock.RLock()
	defer scanRunningLock.RUnlock()

	return isScanRunning
}

func (s *ScanArgs) RunScan() (bool, error) {
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
		go func() {
			defer wg.Done()

			resp, err := github.GetFileContent(s.Repo, file)
			if err != nil {
				fmt.Println(err)
			}
			if err = addVulnToDB(resp, file); err != nil {
				fmt.Println(err)
			}
		}()
	}

	go func() {
		wg.Wait()
		scanRunningLock.Lock()
		defer scanRunningLock.Unlock()

		isScanRunning = false
	}()
	return true, nil
}

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
