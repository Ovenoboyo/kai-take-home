package database

import (
	"database/sql"
	"encoding/json"
	"os"
	"time"
	"vuln-scan-api/internal/logger"

	_ "github.com/mattn/go-sqlite3"
)

type SqliteConn struct {
	db *sql.DB
}

// Initialize sets up the database connection and creates necessary tables.
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

// NewConn creates a new database connection.
// returns: a pointer to SqliteConn
func NewConn() *SqliteConn {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		panic(err)
	}

	return &SqliteConn{
		db: db,
	}
}

// GetTx starts a new database transaction.
// returns: a pointer to sql.Tx and an error if starting the transaction fails
func (s *SqliteConn) GetTx() (*sql.Tx, error) {
	return s.db.Begin()
}

var insertQuery string = `
INSERT INTO vulnerabilities (
	id, severity, cvss, status, package_name, current_version, fixed_version,
	description, published_date, link, risk_factors, source_file, scan_time
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
`

// AddVulnsToDb adds vulnerabilities to the database.
// tx: the database transaction
// vuln: slice of Vulnerabilities to add
// sourceFile: the source file name
// scanTime: the time of the scan
// returns: an error if adding vulnerabilities to DB fails
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

// GetVulnBySeverity retrieves vulnerabilities filtered by severity.
// filters: the filters to apply to the query
// returns: a slice of Vulnerabilities and an error if the query fails
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
			logger.Logger.Error("Failed to parse risk factors arr, ignoring...", "err", err)
		}

		ret = append(ret, vuln)
	}

	return ret, nil
}

// Close closes the database connection.
func (s *SqliteConn) Close() {
	s.db.Close()
}

// DeleteDb deletes the database files.
// Only used for testing
func DeleteDb() {
	files := []string{"data.db", "data.db-shm", "data.db-wal"}

	for _, file := range files {
		os.Remove(file)
	}
}
