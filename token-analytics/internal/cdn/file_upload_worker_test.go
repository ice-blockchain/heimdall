// SPDX-License-Identifier: ice License 1.0

package cdn

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2/fixture"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type (
	mockedClient struct {
		T        testing.TB
		RootPath string
		Data     chan []byte
	}
)

var (
	testPgContainer *fixture.Container
)

func TestMain(m *testing.M) {
	ctx, cancel := context.WithCancel(context.Background())
	testPgContainer = fixture.New(ctx)

	code := m.Run()

	testPgContainer.Close(ctx)
	cancel()

	if code != 0 {
		os.Exit(code)
	}
}

func (m *mockedClient) FileUploadAsync(ctx context.Context, filePath, contentType, fileName string) error {
	m.T.Logf("Mocked async upload file: %s", fileName)
	return nil
}

func (m *mockedClient) DataUploadAsync(ctx context.Context, data []byte, contentType, fileName string) error {
	m.T.Logf("Mocked async upload data for file: %s", fileName)
	return nil
}

func (*mockedClient) HealthCheck(context.Context) error {
	return nil
}

func (m *mockedClient) FileUpload(ctx context.Context, r io.Reader, contentType, fileName string) error {
	m.T.Logf("Mocked upload file: %s", fileName)
	data, err := io.ReadAll(r)
	require.NoError(m.T, err)

	select {
	case m.Data <- data:

	case <-time.After(time.Second * 5):
		m.T.Error("failed to send data, timeout")

	case <-ctx.Done():
		m.T.Error("failed to send data, context done")
	}

	return nil
}

func helperClient(t testing.TB, rqClient riverqueue.Client) (m mockedClient) {
	t.Helper()

	m.T = t
	m.RootPath = t.TempDir()
	m.Data = make(chan []byte, 1)
	riverqueue.RegisterWorker(rqClient.Register(), &uploadWorker{
		Client:   &m,
		RootPath: m.RootPath,
	})

	return m
}

func TestUploadWorker(t *testing.T) {
	t.Parallel()

	const testClientID = "test_cdn_client"

	address, release := testPgContainer.MustTempDB(t.Context())
	defer release()

	rqClient := riverqueue.MustNewClient(t.Context(), "", riverqueue.WithConfig(&riverqueue.Config{
		PrimaryURLs: []string{address},
		ID:          testClientID,
	}))
	cdnClient := helperClient(t, rqClient)
	require.NotNil(t, cdnClient)

	var (
		testFile    = "test.png"
		testContent = []byte("test content")
	)

	require.NoError(t, rqClient.Start(t.Context()))

	t.Run("File by path", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(cdnClient.RootPath, testFile), testContent, 0o644))
		err := rqClient.Push(t.Context(), &uploadWorkerArgs{
			ContentType: "image/png",
			FileName:    testFile,
			Source:      uploadSourceFile,
			Path:        []byte(testFile),
		})
		require.NoError(t, err)

		select {
		case data := <-cdnClient.Data:
			t.Logf("Received uploaded data: %s", string(data))
			require.Equal(t, testContent, data)

		case <-time.After(time.Second * 5):
			t.Error("failed to receive uploaded data, timeout")

		case <-t.Context().Done():
			t.Error("failed to receive uploaded data, context done")
		}
	})
	t.Run("Data upload", func(t *testing.T) {
		err := rqClient.Push(t.Context(), &uploadWorkerArgs{
			ContentType: "image/png",
			FileName:    testFile,
			Path:        testContent,
			Source:      uploadSourceData,
		})
		require.NoError(t, err)

		select {
		case data := <-cdnClient.Data:
			t.Logf("Received uploaded data: %s", string(data))
			require.Equal(t, testContent, data)

		case <-time.After(time.Second * 5):
			t.Error("failed to receive uploaded data, timeout")

		case <-t.Context().Done():
			t.Error("failed to receive uploaded data, context done")
		}
	})

	require.NoError(t, rqClient.Close(t.Context()))
}
