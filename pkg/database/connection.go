package database

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectDB(dsn string) *pgxpool.Pool {
	if dsn == "" {
		log.Fatal("DB_CONNECTION_STRING is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("Failed to create DB pool: %v", err)
	}

	if err := db.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping DB: %v", err)
	}

	return db
}
