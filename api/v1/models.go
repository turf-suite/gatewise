package v1

type User struct {
	Email     string
	Password  string
	Firstname string
	Lastname  string
}

type UserLogin struct {
	Email    string
	Password string
}

type SendVerifyEmailPayload struct {
	Email string `json:"email"`
	Code string `json:"code"`
	Name string `json:"name"`
}

type EmailSentResponse struct {
	Status string `json:"status"`
	Message string `json:"message"`
}