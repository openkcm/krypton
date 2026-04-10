package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/pkg/api/admin"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// Simple krypton server for manual testing and development.
// Not intended for production use (yet).
func main() {
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is required")
	}

	db, err := sql.Open("postgres", dsn)
	handleErr(err, "failed to connect to database")
	defer db.Close()

	store, err := storesql.NewTenant(context.Background(), db)
	handleErr(err, "failed to initialize store")

	err = http.ListenAndServe(addr, admin.NewServerMux(store))
	handleErr(err, "failed to start server")
}

func handleErr(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}
