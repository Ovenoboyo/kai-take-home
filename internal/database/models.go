package database

import "time"

// Vulnerabilities represents the necessary details needed to be stored in the DB
type Vulnerabilities struct {
	ID             string    `json:"id"`
	Severity       string    `json:"severity"`
	Cvss           float64   `json:"cvss"`
	Status         string    `json:"status"`
	PackageName    string    `json:"package_name"`    // Name of the affected package.
	CurrentVersion string    `json:"current_version"` // Version of the package that is currently in use.
	FixedVersion   string    `json:"fixed_version"`   // Version of the package where the vulnerability is fixed.
	Description    string    `json:"description"`     // Description of the vulnerability.
	PublishedDate  time.Time `json:"published_date"`  // Date when the vulnerability was published.
	Link           string    `json:"link"`
	RiskFactors    []string  `json:"risk_factors"` // List of risk factors associated with the vulnerability. Stored as a json string.
}

// Filters represents the criteria used to filter vulnerabilities.
type Filters struct {
	Severity *string `json:"severity"` // Severity level to filter vulnerabilities.
}
