// SPDX-License-Identifier: ice License 1.0

package llm

import (
	_ "embed"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed .testdata/test_validate_big.webp.bin
	testImageWebpBig []byte
	//go:embed .testdata/test_validate_ok.webp.bin
	testImageWebpOK []byte
)

func TestValidateWebpImage(t *testing.T) {
	t.Parallel()

	t.Run("Invalid base64", func(t *testing.T) {
		err := validateWebpImage("invalid-base64")
		require.Error(t, err)
	})
	t.Run("Invalid webp data", func(t *testing.T) {
		err := validateWebpImage(base64.StdEncoding.EncodeToString([]byte("not a webp image")))
		require.Error(t, err)
	})
	t.Run("Large dimensions", func(t *testing.T) {
		b64image := base64.StdEncoding.EncodeToString(testImageWebpBig)
		err := validateWebpImage(b64image)
		require.Error(t, err)
	})
	t.Run("Valid webp image", func(t *testing.T) {
		b64image := base64.StdEncoding.EncodeToString(testImageWebpOK)
		err := validateWebpImage(b64image)
		require.NoError(t, err)
	})
}
