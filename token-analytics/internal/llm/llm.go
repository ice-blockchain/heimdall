// SPDX-License-Identifier: ice License 1.0

package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/image/webp"
)

type (
	Config struct {
		APIKey            string        `yaml:"apiKey"       json:"apiKey"       mapstructure:"apiKey"`
		ImageQuality      string        `yaml:"imageQuality" json:"imageQuality" mapstructure:"imageQuality"`
		MaxRetries        int           `yaml:"maxRetries"   json:"maxRetries"   mapstructure:"maxRetries"`
		TickerCallTimeout time.Duration `yaml:"tickerCallTimeout" json:"tickerCallTimeout" mapstructure:"tickerCallTimeout"`
		ImageCallTimeout  time.Duration `yaml:"imageCallTimeout"  json:"imageCallTimeout"  mapstructure:"imageCallTimeout"`
	}
	Client interface {
		GenerateTokenNameAndTicker(ctx context.Context, creator, content string, images, frames []string) (name, ticker string, err error)
		GenerateTokenImage(ctx context.Context, creator, content, name, ticker string, images, frames []string) (webpB64image string, err error)
	}
)

const (
	defaultMaxRetries       = 15
	defaultVideoFramesCodec = "image/webp"

	MaxImageSideSize = 512
)

var (
	ErrEmptyResponse = errors.New("empty response")
	ErrTooLarge      = errors.New("too large")
)

func New(cfg Config) Client {
	return newOpenAI(cfg)
}

func ValidateWebpImage(b64image string) error {
	data, err := base64.StdEncoding.DecodeString(b64image)
	if err != nil {
		return fmt.Errorf("cannot decode base64 image: %w", err)
	}

	conf, err := webp.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("cannot decode webp image config: %w", err)
	}

	if conf.Height > MaxImageSideSize || conf.Width > MaxImageSideSize {
		return fmt.Errorf("%w: image dimensions too large: %dx%d, max is %d", ErrTooLarge, conf.Width, conf.Height, MaxImageSideSize)
	}

	return nil
}

func capitalizeFirst(s string) string {
	if s == "" {
		return ""
	}

	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size <= 1 {
		return s
	}

	upper := unicode.ToUpper(r)
	if r == upper {
		return s
	}

	return string(upper) + s[size:]
}

func selectFrames(webpFrames []string, maxFrames int) []string {
	if len(webpFrames) <= maxFrames {
		return webpFrames
	}

	step := float64(len(webpFrames)) / float64(maxFrames)
	selected := make([]string, 0, maxFrames)
	for i := range maxFrames {
		index := int(float64(i) * step)
		if index >= len(webpFrames) {
			index = len(webpFrames) - 1
		}
		selected = append(selected, webpFrames[index])
	}
	return selected
}
