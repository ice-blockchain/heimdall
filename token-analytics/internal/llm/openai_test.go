// SPDX-License-Identifier: ice License 1.0

package llm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/eliukblau/pixterm/pkg/ansimage"
	"github.com/lucasb-eyer/go-colorful"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

func isTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func getTerminalSize() (width, height int, err error) {
	if isTerminal() {
		return term.GetSize(int(os.Stdout.Fd()))
	}
	return 80, 24, nil // VT100 terminal size
}

func helperRenderImage(t testing.TB, webpImage []byte) {
	t.Helper()

	tx, ty, err := getTerminalSize()
	if err != nil {
		t.Logf("cannot get terminal size: %v", err)
		return
	}

	const sm = ansimage.ScaleModeFit
	const dm = ansimage.NoDithering

	mc, err := colorful.Hex("#000000")
	if err != nil {
		t.Logf("cannot parse color: %v", err)
		return
	}

	sfy, sfx := 2, 1
	pix, err := ansimage.NewScaledFromReader(bytes.NewReader(webpImage), sfy*ty, sfx*tx, mc, sm, dm)
	if err != nil {
		t.Logf("cannot create ansimage from reader: %v", err)
		return
	}

	if isTerminal() {
		ansimage.ClearTerminal()
	}

	pix.DrawExt(false, false)
	if isTerminal() {
		fmt.Println()
	}
}

func TestLLMProviderOpenAI(t *testing.T) {
	t.Parallel()

	apikey := os.Getenv("TEST_OPENAI_API_KEY")
	if apikey == "" {
		t.Skip("Skipping OpenAI LLM tests, TEST_OPENAI_API_KEY is not set")
	}

	const testPostCreator = "Stephen King"
	const testPostContent = "Just wrote a new horror novel about AI taking over the world. Scariest thing I've ever written! Here is a proto of one of my dogs to save you from the impending doom. 🐶🤖 #AIHorror #NewBook"
	testVideoFrames := []string{
		base64.StdEncoding.EncodeToString(testImageWebpOK),
	}

	client := newOpenAI(Config{
		APIKey:       apikey,
		ImageQuality: "medium",
		MaxRetries:   5,
	})
	require.NotNil(t, client)

	t.Run("Ticker and Name Generation", func(t *testing.T) {
		start := time.Now()
		name, ticker, err := client.GenerateTokenNameAndTicker(t.Context(), testPostCreator, testPostContent, testVideoFrames, nil)
		require.NoError(t, err)
		require.NotEmpty(t, name)
		require.NotEmpty(t, ticker)

		t.Logf("Generated Name: %s, Ticker: %s in %s", name, ticker, time.Since(start))
	})
	t.Run("Image Generation", func(t *testing.T) {
		const testTokenName = "Doom AI"
		const testTokenTicker = "HORROR"

		t.Run("With reference image", func(t *testing.T) {
			start := time.Now()
			b64Image, err := client.GenerateTokenImage(t.Context(), testPostCreator, testPostContent, testTokenName, testTokenTicker, testVideoFrames, nil)
			require.NoError(t, err)
			require.NotEmpty(t, b64Image)
			spent := time.Since(start)

			data, err := base64.StdEncoding.DecodeString(b64Image)
			require.NoError(t, err)
			require.NotZero(t, len(data))

			t.Logf("Generated Image Size: %d bytes in %s", len(data), spent)

			// Ignore possible errors writing the file in tests.
			const writePath = "/tmp/test_openai_generated_token_image.webp"
			os.WriteFile(writePath, data, 0o644) //nolint:errcheck
			t.Logf("Generated image written to: %s", writePath)

			if isTerminal() {
				helperRenderImage(t, data)
			}
		})
		t.Run("Without reference image", func(t *testing.T) {
			now := time.Now()
			b64Image, err := client.GenerateTokenImage(t.Context(), testPostCreator, testPostContent, testTokenName, testTokenTicker, nil, nil)
			require.NoError(t, err)
			require.NotEmpty(t, b64Image)
			spent := time.Since(now)

			data, err := base64.StdEncoding.DecodeString(b64Image)
			require.NoError(t, err)
			require.NotZero(t, len(data))

			t.Logf("Generated Image Size: %d bytes in %s", len(data), spent)

			// Ignore possible errors writing the file in tests.
			const writePath = "/tmp/test_openai_generated_token_image_2.webp"
			os.WriteFile(writePath, data, 0o644) //nolint:errcheck
			t.Logf("Generated image written to: %s", writePath)

			if isTerminal() {
				helperRenderImage(t, data)
			}
		})
	})
}
