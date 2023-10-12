package api

import (
	"database/sql"
	"log"
	"turf-auth/src/utils"

	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

var (
	App   *fiber.App
	DB    *sql.DB
	Redis *redis.Client
	err   error
)

func init() {
	// Redis = redis.NewClient(&redis.Options{
	// 	Addr:     loadEnvVariable("REDIS_CONNECTION"),
	// 	Password: "",
	// 	DB:       0})
	App = fiber.New()
	DB, err = sql.Open("postgres", utils.LoadEnvVariable("POSTGRES_CONNECTION"))
	if err != nil {
		log.Fatalf("Error connecting to postgres database: %v", err)
	}
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		firstname VARCHAR(100),
		lastname VARCHAR(100)
	);
	`
	_, err = DB.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Error creating users table in postgres database: %v", err)
	}
}
