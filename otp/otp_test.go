package otp

import (
	"encoding/base32"
	"testing"

	"github.com/cjlapao/common-go-identity-otp/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type RfcTestMatrixEntry struct {
	Counter uint64
	Code    string
	Mode    common.Algorithm
	Secret  string
}

var (
	sha1Secret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	rfcTestMatrix = []RfcTestMatrixEntry{
		{0, "755224", common.SHA1Algorithm, sha1Secret},
		{1, "287082", common.SHA1Algorithm, sha1Secret},
		{2, "359152", common.SHA1Algorithm, sha1Secret},
		{3, "969429", common.SHA1Algorithm, sha1Secret},
		{4, "338314", common.SHA1Algorithm, sha1Secret},
		{5, "254676", common.SHA1Algorithm, sha1Secret},
		{6, "287922", common.SHA1Algorithm, sha1Secret},
		{7, "162583", common.SHA1Algorithm, sha1Secret},
		{8, "399871", common.SHA1Algorithm, sha1Secret},
		{9, "520489", common.SHA1Algorithm, sha1Secret},
	}
)

func TestGenerateRFCMatrix(t *testing.T) {
	for _, entry := range rfcTestMatrix {
		code, err := GenerateCode(entry.Secret, entry.Counter,
			&OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: entry.Mode,
			})

		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestGenerateWithEmptyOptions(t *testing.T) {
	for _, entry := range rfcTestMatrix {
		code, err := GenerateCode(entry.Secret, entry.Counter, nil)

		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestGenerateWithInvalidCodeSize(t *testing.T) {
	ToggleDebug()
	for _, entry := range rfcTestMatrix {
		code, err := GenerateCode(entry.Secret, entry.Counter, &OtpOptions{
			CodeSize:  0,
			Algorithm: entry.Mode,
		})

		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestValidateRFCTestMatrix(t *testing.T) {

	for _, entry := range rfcTestMatrix {
		valid, err := ValidateCode(entry.Code, entry.Counter, entry.Secret,
			&OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: entry.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
	}
}

func TestValidateWithNilOptions(t *testing.T) {

	for _, entry := range rfcTestMatrix {
		valid, err := ValidateCode(entry.Code, entry.Counter, entry.Secret, nil)
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
	}
}

func TestValidateWithInvalidSecretSize(t *testing.T) {
	code, err := ValidateCode("12345678", rfcTestMatrix[0].Counter, rfcTestMatrix[0].Secret, NewDefaultOtpOptions())

	assert.Equal(t, common.ErrorWrongCodeSize, err)
	assert.False(t, code)
}

func TestValidateWithInvalidOptions(t *testing.T) {
	code, err := ValidateCode("123456", rfcTestMatrix[0].Counter, "%30 ", NewDefaultOtpOptions())

	assert.Equal(t, common.ErrorInvalidSecret, err)
	assert.False(t, code)
}

func TestValidateWithInvalidCode(t *testing.T) {
	code, err := ValidateCode("123456", rfcTestMatrix[0].Counter, rfcTestMatrix[0].Secret, NewDefaultOtpOptions())

	assert.Nil(t, err)
	assert.False(t, code)
}

func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey("SHA1", &OtpKeyOptions{
		Issuer: "foobar",
		UserId: "foobar@example.com",
	})

	assert.NoError(t, err)
	assert.Equal(t, "foobar", k.Issuer())
	assert.Equal(t, "foobar@example.com", k.UserId())
	assert.Equal(t, 16, len(k.Secret()))
	assert.Equal(t, common.SHA1Algorithm.String(), k.Algorithm())

	// spaces in url
	k, err = GenerateKey("SHA1", &OtpKeyOptions{
		Issuer: "foo bar",
		UserId: "foobar@example.com",
	})

	assert.NoError(t, err)
	assert.Contains(t, k.String(), "issuer=foo%20bar")

	// empty issuer
	_, err = GenerateKey("SHA1", &OtpKeyOptions{
		Issuer: "",
		UserId: "foobar@example.com",
	})

	assert.Equal(t, common.ErrorEmptyIssuer, err)

	// empty userid
	_, err = GenerateKey("SHA1", &OtpKeyOptions{
		Issuer: "foobar",
		UserId: "",
	})

	assert.Equal(t, common.ErrorEmptyUserID, err)

	// big secrets
	k, err = GenerateKey("SHA1", &OtpKeyOptions{
		Issuer: "foo bar",
		UserId: "foobar@example.com",
		Secret: NewRandomOtpSecret(20),
	})

	assert.NoError(t, err)
	assert.Equal(t, 32, len(k.Secret()))

	// not random secrets with missing padding
	k, err = GenerateKey("SHA1", &OtpKeyOptions{
		Issuer: "foo bar",
		UserId: "foobar@example.com",
		Secret: NewSecret("abcabcabcabcabcab"),
	})

	assert.NoError(t, err)
	assert.Contains(t, k.Secret(), "=")
}

func TestGenerateKeyWithNilOptions(t *testing.T) {
	k, err := GenerateKey("SHA1", nil)

	assert.Equal(t, common.ErrorNilOtpKeyOptions, err)
	assert.Nil(t, k)
}
