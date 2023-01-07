package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRandomSecret(t *testing.T) {
	result := NewRandomOtpSecret(-1)

	assert.NotNil(t, result)
	assert.Equal(t, uint(10), result.SecretSize)
}
