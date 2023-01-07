package helpers

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadSecret(t *testing.T) {
	secret := PadSecret("te")

	assert.Equal(t, "TE======", secret)
}

func TestPadSecretWithEmptySecret(t *testing.T) {
	secret := PadSecret("")

	assert.Equal(t, "", secret)
}

func TestEncodeQuery(t *testing.T) {
	v := url.Values{}
	v.Set("abc def", "true")
	v.Set("foo", "true")

	result := EncodeQuery(v)
	assert.Equal(t, "abc%20def=true&foo=true", result)
}

func TestEncodeQueryWithEmptyQuery(t *testing.T) {
	result := EncodeQuery(nil)
	assert.Equal(t, "", result)
}
