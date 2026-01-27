// SPDX-License-Identifier: ice License 1.0

package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"

	"github.com/ice-blockchain/wintr/log"
)

type (
	openaiClient struct {
		Cfg    Config
		Client *openai.Client
	}
)

const (
	openaiMaxCreatorNameLength = 256
	openaiMaxPostContentLength = 5000
)

func newOpenAI(cfg Config) *openaiClient {
	cfg.ImageQuality = strings.ToLower(cfg.ImageQuality)

	switch openai.ImageGenerateParamsQuality(cfg.ImageQuality) {
	case openai.ImageGenerateParamsQualityLow, openai.ImageGenerateParamsQualityMedium, openai.ImageGenerateParamsQualityHigh:
		// Valid quality.
	case "":
		// Fallthrough to default if not set.
		cfg.ImageQuality = string(openai.ImageGenerateParamsQualityLow)
	default:
		log.Panic(fmt.Errorf("invalid OpenAI image quality: %s, must be one of: %s",
			cfg.ImageQuality,
			strings.Join([]string{
				string(openai.ImageGenerateParamsQualityLow),
				string(openai.ImageGenerateParamsQualityMedium),
				string(openai.ImageGenerateParamsQualityHigh),
			}, ", "),
		))
	}

	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultMaxRetries
	}

	if cfg.TickerCallTimeout <= 0 {
		cfg.TickerCallTimeout = time.Minute
	}

	if cfg.ImageCallTimeout <= 0 {
		cfg.ImageCallTimeout = 2 * time.Minute
	}

	if envKey := os.Getenv("OPENAI_API_KEY"); cfg.APIKey == "" && envKey != "" {
		log.Info("Using OpenAI API key from environment variable OPENAI_API_KEY")
		cfg.APIKey = envKey
	}

	if cfg.APIKey == "" {
		log.Panic("OpenAI API key is required")
	}

	client := openai.NewClient(
		option.WithAPIKey(cfg.APIKey),
		option.WithMaxRetries(cfg.MaxRetries),
	)

	return &openaiClient{
		Cfg:    cfg,
		Client: &client,
	}
}

func (c *openaiClient) EncodeVideoFramesWebp(webpFrames []string) (contentParts []openai.ChatCompletionContentPartUnionParam, err error) {
	const maxFramesAllowed = 60

	if len(webpFrames) > maxFramesAllowed {
		log.Debug(fmt.Sprintf("truncating video frames from %d to %d for OpenAI request", len(webpFrames), maxFramesAllowed))
		webpFrames = selectFrames(webpFrames, maxFramesAllowed)
	}

	for _, frame := range webpFrames {
		if err = ValidateWebpImage(frame); err != nil {
			return nil, fmt.Errorf("invalid video frame image: %w", err)
		}

		var sb strings.Builder
		sb.WriteString("data:")
		sb.WriteString(defaultVideoFramesCodec)
		sb.WriteString(";base64,")
		sb.WriteString(frame)

		contentParts = append(contentParts, openai.ImageContentPart(openai.ChatCompletionContentPartImageImageURLParam{
			URL: sb.String(),
		}))
	}
	return contentParts, nil
}

func (c *openaiClient) ValidateTextInput(creator, content string) (err error) {
	if len(creator) > openaiMaxCreatorNameLength {
		return fmt.Errorf("%w: creator name too long: %d characters, max is %d", ErrTooLarge, len(creator), openaiMaxCreatorNameLength)
	} else if len(content) > openaiMaxPostContentLength {
		return fmt.Errorf("%w: post content too long: %d characters, max is %d", ErrTooLarge, len(content), openaiMaxPostContentLength)
	}

	return nil
}

func (c *openaiClient) GenerateTokenNameAndTicker(ctx context.Context, creator, content string, images, video []string) (name, ticker string, err error) {
	if err = c.ValidateTextInput(creator, content); err != nil {
		return "", "", err
	}

	prompt, err := executeNameTemplate(creator, content, len(images) > 0, len(video) > 0)
	if err != nil {
		return "", "", fmt.Errorf("cannot build openai prompt: %w", err)
	}

	contentParts := []openai.ChatCompletionContentPartUnionParam{
		openai.TextContentPart(prompt),
	}

	var webpFrames []string
	if len(video) > 0 {
		webpFrames = append(webpFrames, video...)
	}
	if len(images) > 0 {
		webpFrames = append(webpFrames, images...)
	}
	if len(webpFrames) > 0 {
		data, err := c.EncodeVideoFramesWebp(webpFrames)
		if err != nil {
			return "", "", fmt.Errorf("cannot encode webp frames for openai: %w", err)
		}
		contentParts = append(contentParts, data...)
	}

	resp, err := c.Client.Chat.Completions.New(ctx,
		openai.ChatCompletionNewParams{
			Model: openai.ChatModelGPT5Nano,
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.UserMessage(contentParts),
			},
		},
		option.WithRequestTimeout(c.Cfg.TickerCallTimeout),
	)
	if err != nil {
		return "", "", fmt.Errorf("cannot get openai response: %w", err)
	}

	if len(resp.Choices) == 0 || resp.Choices[0].Message.Content == "" {
		return "", "", fmt.Errorf("openai returned empty response: %w", ErrEmptyResponse)
	}

	var result struct {
		Ticker string `json:"ticker"`
		Name   string `json:"name"`
	}
	if err = json.Unmarshal([]byte(resp.Choices[0].Message.Content), &result); err != nil {
		return "", "", fmt.Errorf("cannot unmarshal openai response: %w from content: %s", err, resp.Choices[0].Message.Content)
	}

	return capitalizeFirst(result.Name), strings.ToUpper(result.Ticker), nil
}

func (c *openaiClient) GenerateTokenImage(ctx context.Context, creator, content, name, ticker string, images, video []string) (webpB64image string, err error) {
	if err = c.ValidateTextInput(creator, content); err != nil {
		return "", err
	}

	if len(images) > 0 || len(video) > 0 {
		return c.generateTokenImageFromReferences(ctx, creator, content, name, ticker, images, video)
	}

	return c.generateTokenImageWithGenerate(ctx, creator, content, name, ticker)
}

func (c *openaiClient) generateTokenImageWithGenerate(ctx context.Context, creator, content, name, ticker string) (webpB64image string, err error) {
	prompt, err := executeImageTemplate(creator, content, name, ticker, false, false)
	if err != nil {
		return "", fmt.Errorf("cannot build openai image prompt: %w", err)
	}

	resp, err := c.Client.Images.Generate(ctx,
		openai.ImageGenerateParams{
			Model:        openai.ImageModelGPTImage1_5,
			Prompt:       prompt,
			N:            openai.Int(1),
			OutputFormat: openai.ImageGenerateParamsOutputFormatWebP,
			Quality:      openai.ImageGenerateParamsQuality(c.Cfg.ImageQuality),
			Size:         openai.ImageGenerateParamsSizeAuto,
		},
		option.WithRequestTimeout(c.Cfg.ImageCallTimeout),
	)
	if err != nil {
		return "", fmt.Errorf("cannot get openai image response: %w", err)
	}

	if len(resp.Data) == 0 || resp.Data[0].B64JSON == "" {
		return "", fmt.Errorf("openai returned empty image response: %w", ErrEmptyResponse)
	}

	return resp.Data[0].B64JSON, nil
}

func (c *openaiClient) generateTokenImageFromReferences(ctx context.Context, creator, content, name, ticker string, images, video []string) (webpB64image string, err error) {
	const maxFramesAllowed = 16 // Images.Edit supports up to 16 images.

	prompt, err := executeImageTemplate(creator, content, name, ticker, len(images) > 0, len(video) > 0)
	if err != nil {
		return "", fmt.Errorf("cannot build openai image edit prompt: %w", err)
	}

	var webpFrames []string
	if len(video) > 0 {
		webpFrames = append(webpFrames, video...)
	}
	if len(images) > 0 {
		webpFrames = append(webpFrames, images...)
	}
	if len(webpFrames) > maxFramesAllowed {
		log.Debug(fmt.Sprintf("truncating video frames from %d to %d for OpenAI image edit request", len(webpFrames), maxFramesAllowed))
		webpFrames = selectFrames(webpFrames, maxFramesAllowed)
	}

	imageReaders := make([]io.Reader, 0, len(webpFrames))
	for i, frame := range webpFrames {
		if err = ValidateWebpImage(frame); err != nil {
			return "", fmt.Errorf("invalid video frame image: %w", err)
		}

		decoded, decErr := base64.StdEncoding.DecodeString(frame)
		if decErr != nil {
			return "", fmt.Errorf("cannot decode base64 video frame: %w", decErr)
		}

		imageReaders = append(imageReaders,
			openai.File(bytes.NewReader(decoded), "frame_"+strconv.Itoa(i)+".webp", "image/webp"))
	}

	resp, err := c.Client.Images.Edit(ctx,
		openai.ImageEditParams{
			Model:        openai.ImageModelGPTImage1_5,
			Prompt:       prompt,
			Image:        openai.ImageEditParamsImageUnion{OfFileArray: imageReaders},
			N:            openai.Int(1),
			OutputFormat: openai.ImageEditParamsOutputFormatWebP,
			Quality:      openai.ImageEditParamsQuality(c.Cfg.ImageQuality),
			Size:         openai.ImageEditParamsSizeAuto,
		},
		option.WithRequestTimeout(c.Cfg.ImageCallTimeout),
	)
	if err != nil {
		return "", fmt.Errorf("cannot get openai image edit response: %w", err)
	}

	if len(resp.Data) == 0 || resp.Data[0].B64JSON == "" {
		return "", fmt.Errorf("openai returned empty image edit response: %w", ErrEmptyResponse)
	}

	return resp.Data[0].B64JSON, nil
}
