package otp

import (
	"bytes"
	"image"
	"image/png"
	"net/url"
	"strings"

	"github.com/cjlapao/common-go-identity-otp/common"
	"github.com/skip2/go-qrcode"
)

type OtpKey struct {
	raw string
	url *url.URL
}

func (k *OtpKey) String() string {
	return k.raw
}

func (k *OtpKey) Type() string {
	return k.url.Host
}

func (k *OtpKey) Issuer() string {
	q := k.url.Query()

	issuer := q.Get("issuer")
	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[:i]
}

func (k *OtpKey) UserId() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[i+1:]
}

func (k *OtpKey) Secret() string {
	q := k.url.Query()

	return q.Get("secret")
}

func (k *OtpKey) Algorithm() string {
	q := k.url.Query()

	return q.Get("algorithm")
}

func (k *OtpKey) Image() (image.Image, error) {
	var pngImg []byte
	pngImg, err := qrcode.Encode(k.raw, qrcode.Highest, common.DEFAULT_IMAGE_SIZE)

	if err != nil {
		return nil, err
	}

	img, err := png.Decode(bytes.NewReader(pngImg))
	return img, err
}

func (k *OtpKey) Png() ([]byte, error) {
	var pngImg []byte
	pngImg, err := qrcode.Encode(k.raw, qrcode.Highest, common.DEFAULT_IMAGE_SIZE)

	return pngImg, err
}

func NewKeyFromUrl(keyUrl url.URL) (*OtpKey, error) {
	s := keyUrl.String()

	u, _ := url.Parse(s)

	key := OtpKey{
		raw: s,
		url: u,
	}

	return &key, nil
}
