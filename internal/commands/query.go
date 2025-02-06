package commands

import (
	"encoding/json"
	"fmt"
	"vuln-scan-api/internal/database"
)

type QueryArgs struct {
	Filters database.Filters `json:"filters"`
}

func NewQueryArgs(data []byte) (*QueryArgs, error) {
	var args QueryArgs
	err := json.Unmarshal(data, &args)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return &args, nil
}

func (q *QueryArgs) GetVulnsBySeverity() (ret []byte, err error) {
	conn := database.NewConn()
	defer conn.Close()

	vulns, err := conn.GetVulnBySeverity(q.Filters)
	if err != nil {
		fmt.Println(err)
		return ret, err
	}

	bytes, err := json.Marshal(vulns)
	if err != nil {
		return ret, err
	}

	return bytes, nil
}
