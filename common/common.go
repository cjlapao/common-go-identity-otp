package common

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

const MODULUS_SIZE = 8
const DEFAULT_IMAGE_SIZE = 512

//lint:ignore ST1005 the error code is not going to be used in conjunction with others
var ErrorWrongCodeSize = errors.New("Code length is not of expected length")

//lint:ignore ST1005 the error code is not going to be used in conjunction with others
var ErrorEmptyIssuer = errors.New("Issuer cannot be empty")

var ErrorEmptyUserID = errors.New("UserID cannot be empty")

var ErrorNilOtpKeyOptions = errors.New("OtpKeyOptions cannot be nil")

var ErrorInvalidSecret = errors.New("invalid base32 encoding of the secret")

type PassCodeSize uint

const (
	SixDigits   PassCodeSize = 6
	SevenDigits PassCodeSize = 7
	EightDigits PassCodeSize = 8
)

func (d PassCodeSize) Length() int {
	return int(d)
}

func (d PassCodeSize) String() string {
	return fmt.Sprintf("%d", d)
}

func (d PassCodeSize) Format(value uint64) string {
	f := fmt.Sprintf("%%0%dd", d)
	return fmt.Sprintf(f, value)
}

type Algorithm uint

const (
	SHA1Algorithm Algorithm = iota
	SHA256Algorithm
	SHA512Algorithm
)

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case SHA256Algorithm:
		return crypto.SHA256.New()
	case SHA512Algorithm:
		return crypto.SHA512.New()
	default:
		return crypto.SHA1.New()
	}
}

func (a Algorithm) String() string {
	switch a {
	case SHA256Algorithm:
		return "SHA256"
	case SHA512Algorithm:
		return "SHA512"
	default:
		return "SHA1"
	}
}
