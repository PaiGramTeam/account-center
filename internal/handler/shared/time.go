package shared

import (
	"database/sql"
	"time"
)

// NullTimePtr returns a pointer to the time if valid, nil otherwise.
func NullTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

// MakeNullTime constructs a valid sql.NullTime from the provided time.
func MakeNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{
		Time:  t,
		Valid: true,
	}
}

// ClearNullTime returns an invalid sql.NullTime marker.
func ClearNullTime() sql.NullTime {
	return sql.NullTime{Valid: false}
}
