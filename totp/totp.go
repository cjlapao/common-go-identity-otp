package totp

import (
	"math"
	"time"

	"github.com/cjlapao/common-go-identity-otp/otp"
)

func GenerateCode(secret string, t time.Time, options *TotpOptions) (string, error) {
	if options.Period == 0 {
		options.Period = 30
	}

	counter := getTimeCounter(options.Period, t)

	otpOptions := otp.OtpOptions{
		CodeSize:  options.CodeSize,
		Algorithm: options.Algorithm,
	}

	return otp.GenerateCode(secret, counter, &otpOptions)
}

func GenerateDefault(secret string) (string, error) {
	return GenerateCode(secret, time.Now().UTC(), NewDefaultTotpOptions())
}

func Validate(code string, secret string, t time.Time, options *TotpOptions) (bool, error) {
	if options.Period == 0 {
		options.Period = 30
	}

	counters := []uint64{}
	counter := getTimeCounter(options.Period, t)

	counters = append(counters, counter)
	for i := 1; i <= int(options.Skew); i++ {
		counters = append(counters, uint64(counter+uint64(i)))
		counters = append(counters, uint64(counter-uint64(i)))
	}

	for _, counter := range counters {
		result, err := otp.ValidateCode(code, counter, secret, &otp.OtpOptions{
			CodeSize:  options.CodeSize,
			Algorithm: options.Algorithm,
		})

		if err != nil {
			return false, err
		}

		if result {
			return true, nil
		}
	}

	return false, nil
}

func ValidateDefault(code string, secret string) (bool, error) {
	return Validate(code, secret, time.Now().UTC(), NewDefaultTotpOptions())
}

func GenerateKey(opts *otp.OtpKeyOptions) (*otp.OtpKey, error) {
	return otp.GenerateKey("totp", opts)
}

func GenerateDefaultKey(issuer, userId string) (*otp.OtpKey, error) {
	options := otp.OtpKeyOptions{
		Issuer:  issuer,
		UserId:  userId,
		Secret:  otp.NewRandomOtpSecret(10),
		Options: otp.NewDefaultOtpOptions(),
	}

	return otp.GenerateKey("totp", &options)
}

func getTimeCounter(period uint, t time.Time) uint64 {
	counter := uint64(math.Floor(float64(t.Unix()) / float64(period)))

	return counter
}
