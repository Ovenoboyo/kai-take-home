package commands

import (
	"encoding/json"
	"fmt"
	"vuln-scan-api/internal/database"
	"vuln-scan-api/internal/logger"
)

// QueryArgs parses the POST body from /query
type QueryArgs struct {
	Filters database.Filters `json:"filters"`
}

// NewQueryArgs creates a new QueryArgs instance from JSON data
// data: JSON byte array containing the query arguments
// returns: a pointer to QueryArgs and an error if parsing fails
func NewQueryArgs(data []byte) (*QueryArgs, error) {
	var args QueryArgs
	err := json.Unmarshal(data, &args)
	if err != nil {
		logger.Logger.Error("Failed to parse args for query", "err", err)
		return nil, err
	}

	return &args, nil
}

// GetVulnsBySeverity retrieves vulnerabilities by severity based on the filters
// The response must be sanitized to avoid leaking internals
// returns: a JSON byte array of vulnerabilities and an error if any occurs
func (q *QueryArgs) GetVulnsBySeverity() (ret []byte, err error) {
	conn := database.NewConn()
	defer conn.Close()

	vulns, err := conn.GetVulnBySeverity(q.Filters)
	if err != nil {
		logger.Logger.Error("Failed to get data from DB", "err", err)
		return ret, fmt.Errorf("Failed to get vulnerabilities")
	}

	bytes, err := json.Marshal(vulns)
	if err != nil {
		return ret, fmt.Errorf("Failed to get vulnerabilities")
	}

	return bytes, nil
}
