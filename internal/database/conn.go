package database

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SqliteConn struct {
	db *sql.DB
}

func NewConn() *SqliteConn {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`
		pragma journal_mode = WAL;
		pragma synchronous = normal;
		pragma temp_store = memory;
		pragma mmap_size = 30000000000;
		`)
	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`
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
		);`)
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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	severity=excluded.severity,
	cvss=excluded.cvss,
	status=excluded.status,
	package_name=excluded.package_name,
	current_version=excluded.current_version,
	fixed_version=excluded.fixed_version,
	description=excluded.description,
	published_date=excluded.published_date,
	link=excluded.link,
	risk_factors=excluded.risk_factors,
	source_file=excluded.source_file,
	scan_time=excluded.scan_time;
`

func (s *SqliteConn) AddVulnsToDb(tx *sql.Tx, vuln []Vulnerabilities, source_file string, scan_time time.Time) error {
	for _, v := range vuln {
		riskFactorsJSON, err := json.Marshal(v.RiskFactors)
		if err != nil {
			return err
		}

		_, err = tx.Exec(insertQuery, v.ID, v.Severity, v.Cvss, v.Status, v.PackageName,
			v.CurrentVersion, v.FixedVersion, v.Description, v.PublishedDate.Format(time.RFC3339), v.Link, string(riskFactorsJSON), source_file, scan_time)

		if err != nil {
			tx.Rollback()
			return err
		}
	}

	return nil
}
