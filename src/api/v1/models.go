package v1

type User struct {
	Email string
	Password string
	Firstname string
	Lastname string
}

type UserLogin struct {
	Email string
	Password string
}