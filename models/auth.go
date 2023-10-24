package models

type LoginPayload struct {
	Email    string
	Password string
}

type RegistrationPayload struct {
	Email     string
	Password  string
	Firstname string
	Lastname  string
}
