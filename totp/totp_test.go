package totp

import (
	"encoding/base32"
	"net/url"
	"testing"
	"time"

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
	sha1Secret   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	sha256Secret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	sha512Secret = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcTestMatrix = []RfcTestMatrixEntry{
		{59, "94287082", common.SHA1Algorithm, sha1Secret},
		{59, "46119246", common.SHA256Algorithm, sha256Secret},
		{59, "90693936", common.SHA512Algorithm, sha512Secret},
		{1111111109, "07081804", common.SHA1Algorithm, sha1Secret},
		{1111111109, "68084774", common.SHA256Algorithm, sha256Secret},
		{1111111109, "25091201", common.SHA512Algorithm, sha512Secret},
		{1111111111, "14050471", common.SHA1Algorithm, sha1Secret},
		{1111111111, "67062674", common.SHA256Algorithm, sha256Secret},
		{1111111111, "99943326", common.SHA512Algorithm, sha512Secret},
		{1234567890, "89005924", common.SHA1Algorithm, sha1Secret},
		{1234567890, "91819424", common.SHA256Algorithm, sha256Secret},
		{1234567890, "93441116", common.SHA512Algorithm, sha512Secret},
		{2000000000, "69279037", common.SHA1Algorithm, sha1Secret},
		{2000000000, "90698825", common.SHA256Algorithm, sha256Secret},
		{2000000000, "38618901", common.SHA512Algorithm, sha512Secret},
		{20000000000, "65353130", common.SHA1Algorithm, sha1Secret},
		{20000000000, "77737706", common.SHA256Algorithm, sha256Secret},
		{20000000000, "47863826", common.SHA512Algorithm, sha512Secret},
	}
)

func TestValidate(t *testing.T) {
	for _, tx := range rfcTestMatrix {
		valid, err := Validate(tx.Code, tx.Secret, time.Unix(int64(tx.Counter), 0).UTC(),
			&TotpOptions{
				CodeSize:  common.EightDigits,
				Period:    30,
				Skew:      1,
				Algorithm: tx.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", tx.Code, tx.Mode, tx.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", tx.Code, tx.Mode, tx.Counter)
	}
}

func TestValidateWithNoPeriod(t *testing.T) {
	for _, entry := range rfcTestMatrix {
		valid, err := Validate(entry.Code, entry.Secret, time.Unix(int64(entry.Counter), 0).UTC(),
			&TotpOptions{
				CodeSize:  common.EightDigits,
				Period:    0,
				Skew:      1,
				Algorithm: entry.Mode,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", entry.Code, entry.Mode, entry.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", entry.Code, entry.Mode, entry.Counter)
	}
}

func TestValidateWithInvalidCode(t *testing.T) {
	valid, err := Validate("12345678", rfcTestMatrix[0].Secret, time.Unix(int64(rfcTestMatrix[0].Counter), 0).UTC(),
		&TotpOptions{
			CodeSize:  common.EightDigits,
			Period:    0,
			Skew:      1,
			Algorithm: common.SHA1Algorithm,
		})

	assert.Nil(t, err)
	assert.False(t, valid)
}

func TestValidateSkew(t *testing.T) {
	codes := []RfcTestMatrixEntry{
		{
			29, "94287082", common.SHA1Algorithm, sha1Secret,
		},
		{
			59, "94287082", common.SHA1Algorithm, sha1Secret,
		},
		{
			61, "94287082", common.SHA1Algorithm, sha1Secret,
		},
	}

	for _, code := range codes {
		valid, err := Validate(code.Code, code.Secret, time.Unix(int64(code.Counter), 0).UTC(),
			&TotpOptions{
				Period:    30,
				CodeSize:  common.EightDigits,
				Algorithm: code.Mode,
				Skew:      1,
			})
		require.NoError(t, err,
			"unexpected error totp=%s mode=%v ts=%v", code.Code, code.Mode, code.Counter)
		require.True(t, valid,
			"unexpected totp failure totp=%s mode=%v ts=%v", code.Code, code.Mode, code.Counter)
	}
}

func TestValidateWithInvalidCodeException(t *testing.T) {
	valid, err := Validate("", rfcTestMatrix[0].Secret, time.Unix(int64(rfcTestMatrix[0].Counter), 0).UTC(),
		&TotpOptions{
			CodeSize:  common.EightDigits,
			Period:    0,
			Skew:      1,
			Algorithm: common.SHA1Algorithm,
		})

	assert.Equal(t, common.ErrorWrongCodeSize, err)
	assert.False(t, valid)
}

func TestGenerateCode(t *testing.T) {
	for _, entry := range rfcTestMatrix {
		code, err := GenerateCode(entry.Secret, time.Unix(int64(entry.Counter), 0).UTC(),
			&TotpOptions{
				CodeSize:  common.EightDigits,
				Period:    0,
				Skew:      1,
				Algorithm: entry.Mode,
			})
		assert.Nil(t, err)
		assert.Equal(t, entry.Code, code)
	}
}

func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey(&otp.OtpKeyOptions{
		Issuer: "foobar",
		UserId: "foobar@example.com",
	})

	assert.NoError(t, err)
	assert.Equal(t, "totp", k.Type())
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

func TestGenerateDefaultKey(t *testing.T) {
	k, err := GenerateDefaultKey("foobar", "foobar@example.com")

	assert.NoError(t, err)
	assert.Equal(t, "totp", k.Type())
	assert.Equal(t, "foobar", k.Issuer())
	assert.Equal(t, "foobar@example.com", k.UserId())
	assert.Equal(t, 16, len(k.Secret()))
	assert.Equal(t, common.SHA1Algorithm.String(), k.Algorithm())
}

func TestGoogleLowerCaseSecret(t *testing.T) {
	u, err := url.Parse(`otpauth://totp/Google%3Afoo%40example.com?secret=alt6vmy6svfx4bt4rdmisaiyol6hifca&issuer=Google`)
	require.NoError(t, err)
	w, err := otp.NewKeyFromUrl(*u)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "alt6vmy6svfx4bt4rdmisaiyol6hifca", sec)

	n := time.Now().UTC()
	code, err := GenerateCode(w.Secret(), n, NewDefaultTotpOptions())
	require.NoError(t, err)

	valid, err := ValidateDefault(code, w.Secret())
	require.NoError(t, err)
	require.True(t, valid)
}
