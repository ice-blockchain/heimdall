// SPDX-License-Identifier: ice License 1.0

package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

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
		GenerateTokenNameAndTicker(ctx context.Context, creator, content string, webpFrames []string) (name, ticker string, err error)
		GenerateTokenImage(ctx context.Context, creator, content, name, ticker string, webpFrames []string) (pngB64image string, err error)
	}
)

const (
	defaultMaxRetries       = 15
	defaultVideoFramesCodec = "image/webp"
)

var (
	ErrEmptyResponse = errors.New("empty response")
	ErrTooLarge      = errors.New("too large")
)

func New(cfg Config) Client {
	return newOpenAI(cfg)
}

func validateWebpImage(b64image string) error {
	data, err := base64.StdEncoding.DecodeString(b64image)
	if err != nil {
		return fmt.Errorf("cannot decode base64 image: %w", err)
	}

	conf, err := webp.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("cannot decode webp image config: %w", err)
	}

	const maxHeight = 512
	const maxWidth = 512

	if conf.Height > maxHeight || conf.Width > maxWidth {
		return fmt.Errorf("%w: image dimensions too large: %dx%d, max is %dx%d", ErrTooLarge, conf.Width, conf.Height, maxWidth, maxHeight)
	}

	return nil
}
