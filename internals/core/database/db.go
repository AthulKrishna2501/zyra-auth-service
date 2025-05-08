package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/AthulKrishna2501/zyra-auth-service/internals/app/config"
	"github.com/AthulKrishna2501/zyra-auth-service/internals/core/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func scanDeadRows(db *sql.DB) {
	query := `
		SELECT relname, n_dead_tup 
		FROM pg_stat_all_tables 
		WHERE schemaname = 'public' 
		ORDER BY n_dead_tup DESC;
	`
	rows, err := db.Query(query)
	if err != nil {
		log.Println("Error scanning dead rows:", err)
		return
	}
	defer rows.Close()

	fmt.Println("Dead Rows Report:")
	for rows.Next() {
		var tableName string
		var deadRows int
		if err := rows.Scan(&tableName, &deadRows); err != nil {
			log.Println("Error scanning row:", err)
			continue
		}
		fmt.Printf("Table: %s | Dead Rows: %d\n", tableName, deadRows)
	}
}

func vacuumTables(db *sql.DB) {
	fmt.Println("Running VACUUM on tables with high dead rows...")

	query := `
		SELECT relname 
		FROM pg_stat_all_tables 
		WHERE schemaname = 'public' 
		AND n_dead_tup > 1000;
	`
	rows, err := db.Query(query)
	if err != nil {
		log.Println("Error fetching tables for vacuum:", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			log.Println("Error scanning table name:", err)
			continue
		}

		_, err := db.Exec(fmt.Sprintf("VACUUM ANALYZE %s;", tableName))
		if err != nil {
			log.Printf("Failed to vacuum table %s: %v\n", tableName, err)
		} else {
			log.Printf("Vacuumed table: %s\n", tableName)
		}
	}
}

func StartMonitoring(db *sql.DB, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		scanDeadRows(db)
		vacuumTables(db)
	}
}

func ConnectDatabase(env config.Config) *gorm.DB {
	dbURL := env.DB_URL
	if dbURL == "" {
		dbURL = os.Getenv("DB_URL")
		if dbURL == "" {
			log.Fatal("DB_URL is not set in config or environment variables")
		}
	}
	log.Printf("Attempting to connect to database with DB_URL: %s", dbURL)

	db, err := gorm.Open(postgres.Open(dbURL), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
		return nil
	}

	err = AutoMigrate(db)
	if err != nil {
		log.Fatalf("Error in automigration: %v", err)
		return nil
	}

	log.Println("Successfully connected to database")
	return db
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		models.UserDetails{},
		models.User{},
	)
}
