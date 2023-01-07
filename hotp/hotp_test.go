package hotp

import (
	"encoding/base32"
	"testing"

	"github.com/cjlapao/common-go-identity-otp/common"
	"github.com/cjlapao/common-go-identity-otp/otp"
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
			&otp.OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: entry.Mode,
			})

		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestGenerateRFCMatrixWithSHA256(t *testing.T) {
	for _, entry := range rfcTestMatrix {
		code, err := GenerateCode(entry.Secret, entry.Counter,
			&otp.OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: common.SHA256Algorithm,
			})

		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestGenerateRFCMatrixWithSHA512(t *testing.T) {
	for _, entry := range rfcTestMatrix {
		code, err := GenerateCode(entry.Secret, entry.Counter,
			&otp.OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: common.SHA512Algorithm,
			})

		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestGenerateDefault(t *testing.T) {
	for _, entry := range rfcTestMatrix {
		code, err := GenerateCodeDefault(entry.Secret, entry.Counter)

		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestValidateRFCTestMatrix(t *testing.T) {

	for _, entry := range rfcTestMatrix {
		valid, err := Validate(entry.Code, entry.Counter, entry.Secret,
			&otp.OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: entry.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
	}
}

func TestValidateRFCWithSHA256AlgorithmMatrix(t *testing.T) {

	for _, entry := range rfcTestMatrix {
		valid, err := Validate(entry.Code, entry.Counter, entry.Secret,
			&otp.OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: common.SHA256Algorithm,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
	}
}

func TestValidateRFCWithSHA512AlgorithmMatrix(t *testing.T) {

	for _, entry := range rfcTestMatrix {
		valid, err := Validate(entry.Code, entry.Counter, entry.Secret,
			&otp.OtpOptions{
				CodeSize:  common.SixDigits,
				Algorithm: common.SHA512Algorithm,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
	}
}

func TestValidateDefaultRFCTestMatrix(t *testing.T) {

	for _, entry := range rfcTestMatrix {
		valid, err := ValidateDefault(entry.Code, entry.Counter, entry.Secret)
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v counter=%v", entry.Code, entry.Mode, entry.Counter)
	}
}

func TestGenerateDefaultKey(t *testing.T) {
	type args struct {
		issuer string
		userId string
	}
	tests := []struct {
		name             string
		args             args
		wantIssuer       string
		wantUserId       string
		wantSecretLength int
		wantErr          bool
	}{
		{
			"Issuer with no space",
			args{
				issuer: "foobar",
				userId: "foobar@example.com",
			},
			"foobar",
			"foobar@example.com",
			16,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateDefaultKey(tt.args.issuer, tt.args.userId)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantIssuer, got.Issuer())
			assert.Equal(t, tt.wantUserId, got.UserId())
			assert.Equal(t, tt.wantSecretLength, len(got.Secret()))
			assert.Equal(t, common.SHA1Algorithm.String(), got.Algorithm())
		})
	}
}

func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey(&otp.OtpKeyOptions{
		Issuer: "foobar",
		UserId: "foobar@example.com",
	})

	assert.NoError(t, err)
	assert.Equal(t, "foobar", k.Issuer())
	assert.Equal(t, "foobar@example.com", k.UserId())
	assert.Equal(t, 16, len(k.Secret()))
	assert.Equal(t, common.SHA1Algorithm.String(), k.Algorithm())

	// spaces in url
	k, err = GenerateKey(&otp.OtpKeyOptions{
		Issuer: "foo bar",
		UserId: "foobar@example.com",
	})

	assert.NoError(t, err)
	assert.Contains(t, k.String(), "issuer=foo%20bar")

	// empty issuer
	_, err = GenerateKey(&otp.OtpKeyOptions{
		Issuer: "",
		UserId: "foobar@example.com",
	})

	assert.Equal(t, common.ErrorEmptyIssuer, err)

	// empty userid
	_, err = GenerateKey(&otp.OtpKeyOptions{
		Issuer: "foobar",
		UserId: "",
	})

	assert.Equal(t, common.ErrorEmptyUserID, err)

	// big secrets
	k, err = GenerateKey(&otp.OtpKeyOptions{
		Issuer: "foo bar",
		UserId: "foobar@example.com",
		Secret: otp.NewRandomOtpSecret(20),
	})

	assert.NoError(t, err)
	assert.Equal(t, 32, len(k.Secret()))

	// not random secrets with missing padding
	k, err = GenerateKey(&otp.OtpKeyOptions{
		Issuer: "foo bar",
		UserId: "foobar@example.com",
		Secret: otp.NewSecret("abcabcabcabcabcab"),
	})

	assert.NoError(t, err)
	assert.Contains(t, k.Secret(), "=")
}
