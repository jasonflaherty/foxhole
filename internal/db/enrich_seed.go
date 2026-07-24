package db

import "context"

// CountKEV returns KEV row count.
func (d *DB) CountKEV(ctx context.Context) (int, error) { return d.countTable(ctx, "kev") }

// CountEPSS returns EPSS row count.
func (d *DB) CountEPSS(ctx context.Context) (int, error) { return d.countTable(ctx, "epss") }

// CountLicenses returns license row count.
func (d *DB) CountLicenses(ctx context.Context) (int, error) {
	return d.countTable(ctx, "licenses")
}

func (d *DB) countTable(ctx context.Context, table string) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&n)
	return n, err
}
