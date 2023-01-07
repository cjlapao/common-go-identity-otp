package otp

import "github.com/cjlapao/common-go-identity-otp/common"

type OtpOptions struct {
	CodeSize  common.PassCodeSize
	Algorithm common.Algorithm
}

func NewDefaultOtpOptions() *OtpOptions {
	result := OtpOptions{
		CodeSize:  common.SixDigits,
		Algorithm: common.SHA1Algorithm,
	}

	return &result
}
