package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SqliteConn struct {
	db *sql.DB
}

func Initialize() {
	conn := NewConn()
	defer conn.Close()

	_, err := conn.db.Exec(`
		pragma journal_mode = WAL;
		pragma synchronous = normal;
		pragma temp_store = memory;
		pragma mmap_size = 30000000000;

		CREATE TABLE IF NOT EXISTS vulnerabilities (
		    id TEXT PRIMARY KEY,
		    severity TEXT NOT NULL,
		    cvss REAL NOT NULL,
		    status TEXT NOT NULL,
		    package_name TEXT NOT NULL,
		    current_version TEXT NOT NULL,
		    fixed_version TEXT,
		    description TEXT,
		    published_date DATETIME NOT NULL,
		    link TEXT,
		    risk_factors TEXT,
		    source_file TEXT NOT NULL,
		    scan_time DATETIME NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities (severity);
		`)

	if err != nil {
		panic(err)
	}

}

func NewConn() *SqliteConn {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		panic(err)
	}

	return &SqliteConn{
		db: db,
	}
}

func (s *SqliteConn) GetTx() (*sql.Tx, error) {
	return s.db.Begin()
}

var insertQuery string = `
INSERT INTO vulnerabilities (
	id, severity, cvss, status, package_name, current_version, fixed_version,
	description, published_date, link, risk_factors, source_file, scan_time
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

func (s *SqliteConn) AddVulnsToDb(tx *sql.Tx, vuln []Vulnerabilities, sourceFile string, scanTime time.Time) error {
	for _, v := range vuln {
		riskFactorsJSON, err := json.Marshal(v.RiskFactors)
		if err != nil {
			return err
		}

		_, err = tx.Exec(insertQuery, v.ID, v.Severity, v.Cvss, v.Status, v.PackageName,
			v.CurrentVersion, v.FixedVersion, v.Description, v.PublishedDate.Format(time.RFC3339), v.Link, string(riskFactorsJSON), sourceFile, scanTime)

		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return nil
}

var severityFilterQuery string = `SELECT id, severity, cvss, status, package_name, current_version, fixed_version,
			  description, published_date, link, risk_factors
			  FROM vulnerabilities WHERE 1=1 `

func (s *SqliteConn) GetVulnBySeverity(filters Filters) ([]Vulnerabilities, error) {
	ret := []Vulnerabilities{}

	var bind []any = make([]any, 0, 0)

	query := severityFilterQuery
	if filters.Severity != nil {
		query += "AND severity = ?"
		bind = append(bind, *filters.Severity)
	}

	rows, err := s.db.Query(query, bind...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var vuln Vulnerabilities
		var riskFactors []byte
		if err := rows.Scan(&vuln.ID, &vuln.Severity, &vuln.Cvss, &vuln.Status, &vuln.PackageName,
			&vuln.CurrentVersion, &vuln.FixedVersion, &vuln.Description, &vuln.PublishedDate,
			&vuln.Link, &riskFactors); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(riskFactors, &vuln.RiskFactors); err != nil {
			fmt.Println(err)
		}

		ret = append(ret, vuln)
	}

	return ret, nil
}

func (s *SqliteConn) Close() {
	s.db.Close()
}
