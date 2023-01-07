package interfaces

type OtpService interface {
	Algorithm() string
	ValidateCode(code string, counter uint, secret string)
	GenerateCode(code string, secret string)
}
