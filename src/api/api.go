package api

import (
	"database/sql"
	"log"

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
	DB, err = sql.Open("postgres", loadEnvVariable("POSTGRES_CONNECTION"))
	if err != nil {
		log.Fatal(err)
	}
}
