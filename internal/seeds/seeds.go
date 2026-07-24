package seeds

import _ "embed"

// OSV is a small built-in advisory set for offline/dev bootstrap.
//
//go:embed osv.json
var OSV []byte

// NVD is a small built-in CVE set for offline/dev bootstrap.
//
//go:embed nvd.json
var NVD []byte
