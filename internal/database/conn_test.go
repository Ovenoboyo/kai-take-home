package database

import (
	"testing"
)

func TestOpenConn(t *testing.T) {
	defer DeleteDb()

	Initialize()

	conn := NewConn()

	if conn == nil {
		t.Fatalf("Got nil conn, should've paniced")
	}

	// Can check if table exists in DB
}
