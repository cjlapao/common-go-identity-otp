package otp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefaultOtpKeyOptions(t *testing.T) {
	type args struct {
		issuer string
		userId string
	}
	tests := []struct {
		name           string
		args           args
		wantIssuer     string
		wantUserId     string
		wantSecretSize int
		wantAlgorithm  string
	}{
		{
			"default is correct",
			args{
				issuer: "foobar",
				userId: "foobar@example.com",
			},
			"foobar",
			"foobar@example.com",
			16,
			"SHA1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDefaultOtpKeyOptions(tt.args.issuer, tt.args.userId)
			assert.Equal(t, tt.wantIssuer, got.Issuer)
			assert.Equal(t, tt.wantUserId, got.UserId)
			assert.Equal(t, tt.wantSecretSize, len(got.Secret.value))
			assert.Equal(t, tt.wantAlgorithm, got.Options.Algorithm.String())
		})
	}
}
