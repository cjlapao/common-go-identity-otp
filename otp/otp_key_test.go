package otp

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyType(t *testing.T) {
	keyUrl := url.URL{
		Scheme: "otpauth",
		Host:   "hotp",
		Path:   "foobar:foobar@example.com",
	}
	key, err := NewKeyFromUrl(keyUrl)

	assert.Nil(t, err)
	assert.Equal(t, "hotp", key.Type())
}

func TestKeyIssuerFromPath(t *testing.T) {
	keyUrl := url.URL{
		Scheme: "otpauth",
		Host:   "hotp",
		Path:   "foobar:foobar@example.com",
	}
	key, err := NewKeyFromUrl(keyUrl)

	assert.Nil(t, err)
	assert.Equal(t, "foobar", key.Issuer())
}

func TestKeyParse(t *testing.T) {
	keyUrl := url.URL{
		Scheme: "",
		Host:   "",
	}
	key, err := NewKeyFromUrl(keyUrl)

	assert.Nil(t, err)
	assert.Equal(t, "", key.UserId())
}

func TestKeyEmptyIssuer(t *testing.T) {
	keyUrl := url.URL{
		Scheme: "otpauth",
		Host:   "hotp",
		Path:   "foobar@example.com",
	}
	key, err := NewKeyFromUrl(keyUrl)

	assert.Nil(t, err)
	assert.Equal(t, "", key.Issuer())
}

func TestKeyEmptyUser(t *testing.T) {
	keyUrl := url.URL{
		Scheme: "otpauth",
		Host:   "hotp",
		Path:   "foobar@example.com",
	}
	key, err := NewKeyFromUrl(keyUrl)

	assert.Nil(t, err)
	assert.Equal(t, "", key.UserId())
}

func TestKeyIssuerInvalidImage(t *testing.T) {
	key := OtpKey{
		raw: "",
		url: nil,
	}

	img, err := key.Image()

	assert.Nil(t, img)
	assert.NotNil(t, err)
}

func TestKeyIssuerImage(t *testing.T) {
	keyUrl := url.URL{
		Scheme: "otpauth",
		Host:   "hotp",
		Path:   "foobar@example.com",
	}
	key, err := NewKeyFromUrl(keyUrl)
	assert.Nil(t, err)

	img, err := key.Image()

	assert.Nil(t, err)
	assert.NotNil(t, img)
}

func TestKeyIssuerInvalidPngImage(t *testing.T) {
	key := OtpKey{
		raw: "",
		url: nil,
	}

	img, err := key.Png()

	assert.Nil(t, img)
	assert.NotNil(t, err)
}

func TestKeyIssuerPngImage(t *testing.T) {
	keyUrl := url.URL{
		Scheme: "otpauth",
		Host:   "hotp",
		Path:   "foobar@example.com",
	}
	key, err := NewKeyFromUrl(keyUrl)
	assert.Nil(t, err)

	img, err := key.Png()

	assert.Nil(t, err)
	assert.NotNil(t, img)
}
