package hotp

import (
	"github.com/cjlapao/common-go-identity-otp/common"
	"github.com/cjlapao/common-go-identity-otp/otp"
)

func GenerateCode(secret string, counter uint64, options *otp.OtpOptions) (string, error) {
	switch options.Algorithm {
	case common.SHA256Algorithm, common.SHA512Algorithm:
		options.Algorithm = common.SHA1Algorithm
	}

	return otp.GenerateCode(secret, counter, options)
}

func GenerateCodeDefault(secret string, counter uint64) (string, error) {
	return GenerateCode(secret, counter, otp.NewDefaultOtpOptions())
}

func Validate(code string, counter uint64, secret string, options *otp.OtpOptions) (bool, error) {
	switch options.Algorithm {
	case common.SHA256Algorithm, common.SHA512Algorithm:
		options.Algorithm = common.SHA1Algorithm
	}

	return otp.ValidateCode(code, counter, secret, options)
}

func ValidateDefault(code string, counter uint64, secret string) (bool, error) {
	return Validate(code, counter, secret, otp.NewDefaultOtpOptions())
}

func GenerateKey(opts *otp.OtpKeyOptions) (*otp.OtpKey, error) {
	return otp.GenerateKey("hotp", opts)
}

func GenerateDefaultKey(issuer, userId string) (*otp.OtpKey, error) {
	options := otp.OtpKeyOptions{
		Issuer:  issuer,
		UserId:  userId,
		Secret:  otp.NewRandomOtpSecret(10),
		Options: otp.NewDefaultOtpOptions(),
	}

	return otp.GenerateKey("hotp", &options)
}
