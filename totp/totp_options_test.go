package totp

import (
	"reflect"
	"testing"

	"github.com/cjlapao/common-go-identity-otp/common"
)

func TestNewDefaultTotpOptions(t *testing.T) {
	tests := []struct {
		name string
		want *TotpOptions
	}{
		{
			"default options",
			&TotpOptions{
				Period:    30,
				Skew:      1,
				CodeSize:  common.SixDigits,
				Algorithm: common.SHA1Algorithm,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDefaultTotpOptions(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDefaultTotpOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}
