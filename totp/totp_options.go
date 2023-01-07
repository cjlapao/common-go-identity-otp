package totp

import "github.com/cjlapao/common-go-identity-otp/common"

type TotpOptions struct {
	Period    uint
	Skew      uint
	CodeSize  common.PassCodeSize
	Algorithm common.Algorithm
}

func NewDefaultTotpOptions() *TotpOptions {
	result := TotpOptions{
		Period:    30,
		Skew:      1,
		CodeSize:  common.SixDigits,
		Algorithm: common.SHA1Algorithm,
	}

	return &result
}
