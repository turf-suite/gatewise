package repositories

import (
	"database/sql"
	"turf-gatewise/models"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type UserManager interface {
	CreateNewUser(user *models.User) error
	DeleteUser(id uuid.UUID) error
	GetUserLoginDetails(email string) (models.UserLoginQuery, error)
}

type UserRepository struct {
	Db *sql.DB
}

func (repo *UserRepository) CreateNewUser(user *models.User) error {
	userQuery := `
		INSERT INTO users (id, firstname, lastname, email, password)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := repo.Db.Exec(
		userQuery,
		user.Id,
		user.FirstName,
		user.LastName,
		user.Email,
		user.Password)
	return err
}

func (repo *UserRepository) GetUserLoginDetails(email string) (models.UserLoginQuery, error) {
	userData := repo.Db.QueryRow("SELECT id, password FROM users WHERE email = $1", email)
	var (
		id       []byte
		password string
	)
	err := userData.Scan(&id, &password)
	if err != nil {
		return models.UserLoginQuery{}, err
	} else {
		return models.UserLoginQuery{Id: id, Email: email, Password: password}, nil
	}
}

func (repo *UserRepository) DeleteUser(id uuid.UUID) error {
	_, err := repo.Db.Exec("DELETE FROM users WHERE id = $0", id)
	return err
}
