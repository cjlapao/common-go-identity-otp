package otp

import (
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/cjlapao/common-go-identity-otp/common"
	"github.com/cjlapao/common-go-identity-otp/helpers"
	"github.com/cjlapao/common-go/guard"
)

var debug = false

func ToggleDebug() {
	debug = !debug
}

func GenerateCode(secret string, counter uint64, options *OtpOptions) (string, error) {
	if options == nil {
		options = NewDefaultOtpOptions()
	}

	if options.CodeSize == 0 {
		options.CodeSize = common.SixDigits
	}

	secret = helpers.PadSecret(secret)

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", common.ErrorInvalidSecret
	}

	buff := make([]byte, common.MODULUS_SIZE)
	mac := hmac.New(options.Algorithm.Hash, secretBytes)
	binary.BigEndian.PutUint64(buff, counter)

	if debug {
		fmt.Printf("counter=%v\n", counter)
		fmt.Printf("buf=%v\n", buff)
	}

	mac.Write(buff)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	l := options.CodeSize.Length()
	mod := uint64(value % int64(math.Pow10(l)))

	if debug {
		fmt.Printf("offset=%v\n", offset)
		fmt.Printf("value=%v\n", value)
		fmt.Printf("mod'ed=%v\n", mod)
	}

	return options.CodeSize.Format(mod), nil
}

func ValidateCode(code string, counter uint64, secret string, options *OtpOptions) (bool, error) {
	code = strings.TrimSpace(code)
	if options == nil {
		options = NewDefaultOtpOptions()
	}

	if len(code) != options.CodeSize.Length() {
		return false, common.ErrorWrongCodeSize
	}

	genCode, err := GenerateCode(secret, counter, options)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(code), []byte(genCode)) == 1 {
		return true, nil
	}

	return false, nil
}

func GenerateKey(algorithm string, opts *OtpKeyOptions) (*OtpKey, error) {
	if opts == nil {
		return nil, common.ErrorNilOtpKeyOptions
	}

	if err := guard.EmptyOrNil(opts.Issuer); err != nil {
		return nil, common.ErrorEmptyIssuer
	}

	if err := guard.EmptyOrNil(opts.UserId); err != nil {
		return nil, common.ErrorEmptyUserID
	}

	if opts.Secret == nil {
		opts.Secret = NewRandomOtpSecret(10)
	}

	if opts.Options == nil {
		opts.Options = NewDefaultOtpOptions()
	}

	keyUrl := url.Values{}
	keyUrl.Set("secret", opts.Secret.Value())
	keyUrl.Set("issuer", opts.Issuer)
	keyUrl.Set("algorithm", opts.Options.Algorithm.String())
	keyUrl.Set("digits", opts.Options.CodeSize.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     strings.ToLower(algorithm),
		Path:     fmt.Sprintf("/%s:%s", opts.Issuer, opts.UserId),
		RawQuery: helpers.EncodeQuery(keyUrl),
	}

	key, err := NewKeyFromUrl(u)

	return key, err
}
