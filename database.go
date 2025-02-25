package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// Initialize DB Connection
func InitDB() *sql.DB {
	db, err := sql.Open("sqlite3", "users.db")
	if err != nil {
		log.Fatal(err)
	}

	// Create Users Table
	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		google_id TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		picture TEXT
	);`
	_, err = db.Exec(createUsersTable)
	if err != nil {
		log.Fatal(err)
	}

	// Create Messages Table with status field
	createMessagesTableSQL := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender_id TEXT NOT NULL,
		receiver_id TEXT NOT NULL,
		content TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT DEFAULT 'sent',
		FOREIGN KEY(sender_id) REFERENCES users(google_id),
		FOREIGN KEY(receiver_id) REFERENCES users(google_id)
	);`
	_, err = db.Exec(createMessagesTableSQL)
	if err != nil {
		log.Fatal("Failed to create messages table:", err)
	}

	// Try to add status column to existing table (if table exists but no status column)
	_, err = db.Exec("ALTER TABLE messages ADD COLUMN status TEXT DEFAULT 'sent';")
	// Ignore error since column might already exist

	fmt.Println("Database initialized successfully!")
	return db
}
