package otp

type OtpKeyOptions struct {
	Issuer  string
	UserId  string
	Secret  *OtpSecret
	Options *OtpOptions
}

func NewDefaultOtpKeyOptions(issuer string, userId string) *OtpKeyOptions {
	result := OtpKeyOptions{
		Issuer:  issuer,
		UserId:  userId,
		Secret:  NewRandomOtpSecret(10),
		Options: NewDefaultOtpOptions(),
	}

	return &result
}
