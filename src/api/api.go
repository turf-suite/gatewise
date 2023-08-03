package api

import (
	"github.com/gofiber/fiber/v2"
	"database/sql"
	_ "github.com/lib/pq"
	"log"
)

var (
	App *fiber.App
	DB *sql.DB
)

func init() {
	App = fiber.New()
	var err error
	DB, err = sql.Open("postgres", "postgres://postgres:CzRtCrWYFHPzBh37OpcQ@containers-us-west-43.railway.app:5653/railway")
	if err != nil {
		log.Fatal(err)
	}
}