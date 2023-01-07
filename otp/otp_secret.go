package otp

import (
	"encoding/base32"

	cryptorand "github.com/cjlapao/common-go-cryptorand"
	"github.com/cjlapao/common-go-identity-otp/helpers"
)

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

type OtpSecret struct {
	SecretSize uint
	value      string
}

func NewSecret(secret string) *OtpSecret {
	result := OtpSecret{}
	result.value = helpers.PadSecret(secret)
	result.SecretSize = uint(len(result.value))

	return &result
}

func NewRandomOtpSecret(size int) *OtpSecret {
	if size <= 0 {
		size = 10
	}

	rand := cryptorand.New().Rand
	secret := make([]byte, size)
	rand.Read(secret)

	result := OtpSecret{
		SecretSize: uint(size),
		value:      b32NoPadding.EncodeToString(secret),
	}

	return &result
}

func (s *OtpSecret) Value() string {
	return s.value
}
