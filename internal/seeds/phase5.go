package seeds

import (
	_ "embed"
	"encoding/json"
)

//go:embed kev.json
var KEVJSON []byte

//go:embed epss.json
var EPSSJSON []byte

//go:embed licenses.json
var LicensesJSON []byte

// KEVRecord is a CISA KEV seed row.
type KEVRecord struct {
	CVEID           string `json:"cve_id"`
	VendorProject   string `json:"vendor_project"`
	Product         string `json:"product"`
	DateAdded       string `json:"date_added"`
	DueDate         string `json:"due_date"`
	KnownRansomware string `json:"known_ransomware"`
}

// EPSSRecord is an EPSS seed row.
type EPSSRecord struct {
	CVEID      string  `json:"cve_id"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// LicenseSeed is a license risk seed row.
type LicenseSeed struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	SPDX        string `json:"spdx_id"`
	Risk        string `json:"risk"`
	OSIApproved bool   `json:"osi_approved"`
}

// KEVRecords parses embedded KEV seeds.
func KEVRecords() ([]KEVRecord, error) {
	var out []KEVRecord
	return out, json.Unmarshal(KEVJSON, &out)
}

// EPSSRecords parses embedded EPSS seeds.
func EPSSRecords() ([]EPSSRecord, error) {
	var out []EPSSRecord
	return out, json.Unmarshal(EPSSJSON, &out)
}

// LicenseRecords parses embedded license seeds.
func LicenseRecords() ([]LicenseSeed, error) {
	var out []LicenseSeed
	return out, json.Unmarshal(LicensesJSON, &out)
}
