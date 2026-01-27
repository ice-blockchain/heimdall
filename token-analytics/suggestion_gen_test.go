// SPDX-License-Identifier: ice License 1.0

package tokenanalytics

import (
	"context"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/heimdall/token-analytics/internal/cdn"
	"github.com/ice-blockchain/heimdall/token-analytics/internal/llm"
)

type (
	mockedCDNClient struct {
		TB            testing.TB
		StateObserver cdn.StateObserver
		Ready         chan string
	}
	mockedLLMClient struct {
		TB testing.TB
	}
)

var (
	_ cdn.Client = (*mockedCDNClient)(nil)
	_ llm.Client = (*mockedLLMClient)(nil)
)

func (client *mockedCDNClient) TargetURL(fileName string) string {
	return "https://mocked.cdn/" + fileName
}

func (client *mockedCDNClient) SubmitFileUploadJob(ctx context.Context, data []byte, contentType, fileName string, m *cdn.Metadata) error {
	client.TB.Logf("mocked async upload data for file: %s", fileName)
	if client.StateObserver != nil {
		client.StateObserver.OnUploadCompleted(ctx, fileName, "https://mocked.cdn/"+fileName, m)
		select {
		case client.Ready <- fileName:
		default:
			client.TB.Log("cdn ready channel is full, skipping notification")
		}
	}
	return nil
}

func (m *mockedCDNClient) FileUpload(ctx context.Context, data io.Reader, contentType, fileName string) (string, error) {
	return m.TargetURL(fileName), nil
}

func (*mockedCDNClient) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockedCDNClient) Observer() cdn.StateObserver {
	return m.StateObserver
}

func (client *mockedLLMClient) GenerateTokenNameAndTicker(ctx context.Context, creator, content string, images, frames []string) (name, ticker string, err error) {
	client.TB.Logf("mocked GenerateTokenNameAndTicker called with creator: %s, content: %s, frames count: %d", creator, content, len(images)+len(frames))
	return "Mocked Token Name", "MTN", nil
}

func (client *mockedLLMClient) GenerateTokenImage(ctx context.Context, creator, content, name, ticker string, images, frames []string) (webpB64image string, err error) {
	client.TB.Logf("mocked GenerateTokenImage called with creator: %s, content: %s, name: %s, ticker: %s, frames count: %d", creator, content, name, ticker, len(images)+len(frames))
	return base64.StdEncoding.EncodeToString([]byte("mocked_webp_image_data")), nil
}

func TestGenerateTokenSuggestion(t *testing.T) {
	t.Parallel()

	db, connString, release := helperCreateDBWithConnString(t)
	defer release()

	ta := helperNewForTestWithConnString(t, db, connString)
	cdnClient := &mockedCDNClient{StateObserver: ta, TB: t, Ready: make(chan string, 1)}
	llmClient := &mockedLLMClient{TB: t}

	ta.llmClient = llmClient
	ta.cdnClient = cdnClient
	defer ta.Close()

	t.Run("OK", func(t *testing.T) {
		data := &CreationDetailsData{
			ContentID: "TEST_CONTENT_HAPPY",
			Content:   "Test token with complete metadata",
			Creator:   CreationDetailsCreator{Name: "John Doe"},
		}

		result, err := ta.GenerateTokenSuggestion(t.Context(), data)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.EqualValues(t, TokenDetailsGenerationStatusGeneratingPicture, result.Status)
		require.Equal(t, "MTN", result.Ticker)
		require.Equal(t, "Mocked Token Name", result.Name)
		require.NotEmpty(t, result.Picture)

		select {
		case <-cdnClient.Ready:
		case <-time.After(time.Minute):
			t.Fatal("timeout waiting for CDN upload to complete")
		}

		result2, err := ta.GenerateTokenSuggestion(t.Context(), data)
		require.NoError(t, err)
		require.NotNil(t, result2)
		require.EqualValues(t, TokenDetailsGenerationStatusCompleted, result2.Status)
		require.Equal(t, "MTN", result2.Ticker)
		require.Equal(t, "Mocked Token Name", result2.Name)
		require.NotEmpty(t, result2.Picture)
		require.Equal(t, result.Picture, result2.Picture)
	})
}
