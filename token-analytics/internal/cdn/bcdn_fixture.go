// SPDX-License-Identifier: ice License 1.0

package cdn

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func VerifyFileOnCdn(tb testing.TB, ctx context.Context, cdnClient Client, fileName string) {
	tb.Helper()

	url := cdnClient.(*client).CdnDownloadURL(fileName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	require.NoError(tb, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(tb, err)
	require.Equal(tb, http.StatusOK, resp.StatusCode, url)

	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(tb, err)
	require.NotEmpty(tb, bodyBytes)
	require.NoError(tb, resp.Body.Close())
}

func VerifyFileDeletedOnCdn(tb testing.TB, ctx context.Context, cdnClient Client, fileName string) {
	tb.Helper()

	url := cdnClient.(*client).CdnDownloadURL(fileName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	require.NoError(tb, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(tb, err)
	require.Equal(tb, http.StatusNotFound, resp.StatusCode, url)
	require.NoError(tb, resp.Body.Close())
}
