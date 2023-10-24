package repositories

import (
	"database/sql"
	"turf-gatewise/models"

	_ "github.com/lib/pq"
)

type UserManager interface {
	CreateNew(user *models.User) error
	GetUserLoginDetails(email string) (models.UserLoginQuery, error)
}

type UserRepository struct {
	db *sql.DB
}

func (repo *UserRepository) CreateNewUser(user *models.User) error {
	userQuery := `
		INSERT INTO users (id, firstname, lastname, email, password)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := repo.db.Exec(
		userQuery,
		user.Id,
		user.FirstName,
		user.LastName,
		user.Email,
		user.Password)
	return err
}

func (repo *UserRepository) GetUserLoginDetails(email string) (models.UserLoginQuery, error) {
	userData := repo.db.QueryRow("SELECT id, password FROM users WHERE email = $1", email)
	var (
		id       string
		password string
	)
	err := userData.Scan(&id, &password)
	if err != nil {
		return models.UserLoginQuery{}, err
	} else {
		return models.UserLoginQuery{Id: id, Email: email, Password: password}, nil
	}
}
