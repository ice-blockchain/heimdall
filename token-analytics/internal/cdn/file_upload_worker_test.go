// SPDX-License-Identifier: ice License 1.0

package cdn

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ice-blockchain/wintr/connectors/storage/v2/fixture"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type (
	mockedClient struct {
		T         testing.TB
		RootPath  string
		Data      chan []byte
		Observer  StateObserver
		FailCount int32
	}
	mockedObserver struct {
		T             testing.TB
		FnOnCompleted func(ctx context.Context, fileName, downloadURL string)
		FnOnError     func(ctx context.Context, fileName string, err error, attempt int)
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

func (m *mockedClient) FileUpload(ctx context.Context, r io.Reader, contentType, fileName string) (string, error) {
	m.T.Logf("Mocked upload file: %s", fileName)
	data, err := io.ReadAll(r)
	require.NoError(m.T, err)

	if n := atomic.AddInt32(&m.FailCount, -1); n >= 0 {
		return "", fmt.Errorf("simulated upload error for file: %s [n=%d]", fileName, n)
	}

	select {
	case m.Data <- data:

	case <-time.After(time.Second * 5):
		m.T.Fatal("failed to send data, timeout")

	case <-ctx.Done():
		m.T.Fatal("failed to send data, context done")
	}

	return "download://" + fileName, nil
}

func (m *mockedClient) observer() StateObserver {
	return m.Observer
}

func (o *mockedObserver) OnUploadCompleted(ctx context.Context, fileName, downloadURL string) {
	o.T.Logf("Observer: upload completed for file: %s: %s", fileName, downloadURL)
	if o.FnOnCompleted != nil {
		o.FnOnCompleted(ctx, fileName, downloadURL)
	}
}

func (o *mockedObserver) OnUploadError(ctx context.Context, fileName string, err error, attempt int) {
	o.T.Logf("Observer: upload error for file: %s: %v, attempt: %d", fileName, err, attempt)
	if o.FnOnError != nil {
		o.FnOnError(ctx, fileName, err, attempt)
	}
}

func helperNewClient(t testing.TB) (*mockedClient, *mockedObserver) {
	t.Helper()

	var m mockedClient
	m.T = t
	m.RootPath = t.TempDir()
	m.Data = make(chan []byte, 1)

	var o = mockedObserver{T: t}
	m.Observer = &o

	return &m, &o
}

func helperRegisterUploadWorker(t testing.TB, rqClient riverqueue.Client, cdnClient Client, rootPath string) {
	t.Helper()

	riverqueue.RegisterWorker(rqClient.Register(), &uploadWorker{
		Client:        cdnClient,
		RootPath:      rootPath,
		JobRetryAfter: time.Second,
	})
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
	client, observer := helperNewClient(t)
	helperRegisterUploadWorker(t, rqClient, client, client.RootPath)

	var (
		testFile    = "test.png"
		testContent = []byte("test content")
	)

	require.NoError(t, rqClient.Start(t.Context()))

	t.Run("File by path", func(t *testing.T) {
		observerChan := make(chan string, 1)
		observer.FnOnCompleted = func(ctx context.Context, fileName, downloadURL string) {
			t.Logf("Custom observer: upload completed for file: %s: %s", fileName, downloadURL)
			select {
			case observerChan <- downloadURL:

			case <-time.After(time.Second * 5):
				t.Fatal("failed to send to observerChan, timeout")
			}
		}
		defer func() {
			observer.FnOnCompleted = nil
		}()

		require.NoError(t, os.WriteFile(filepath.Join(client.RootPath, testFile), testContent, 0o644))
		err := rqClient.Push(t.Context(), &uploadWorkerArgs{
			ContentType: "image/png",
			FileName:    testFile,
			Source:      uploadSourceFile,
			Path:        []byte(testFile),
		})
		require.NoError(t, err)

		select {
		case data := <-client.Data:
			t.Logf("Received uploaded data: %s", string(data))
			require.Equal(t, testContent, data)

		case <-time.After(time.Second * 5):
			t.Fatal("failed to receive uploaded data, timeout")

		case <-t.Context().Done():
			t.Fatal("failed to receive uploaded data, context done")
		}

		select {
		case downloadURL := <-observerChan:
			t.Logf("Received download URL from observer: %s", downloadURL)
			require.Equal(t, "download://"+testFile, downloadURL)

		case <-time.After(time.Second * 5):
			t.Fatal("failed to receive download URL from observer, timeout")

		case <-t.Context().Done():
			t.Fatal("failed to receive download URL from observer, context done")
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
		case data := <-client.Data:
			t.Logf("Received uploaded data: %s", string(data))
			require.Equal(t, testContent, data)

		case <-time.After(time.Second * 5):
			t.Fatal("failed to receive uploaded data, timeout")

		case <-t.Context().Done():
			t.Fatal("failed to receive uploaded data, context done")
		}
	})

	require.NoError(t, rqClient.Close(t.Context()))
}

func TestUploadWorkerErrorHandler(t *testing.T) {
	t.Parallel()

	const testClientID = "test_cdn_client_errors"

	address, release := testPgContainer.MustTempDB(t.Context())
	defer release()

	rqClient := riverqueue.MustNewClient(t.Context(), "", riverqueue.WithConfig(&riverqueue.Config{
		PrimaryURLs: []string{address},
		ID:          testClientID,
	}))

	const failNumber = 2

	failingClient, observer := helperNewClient(t)
	failingClient.FailCount = failNumber
	helperRegisterUploadWorker(t, rqClient, failingClient, failingClient.RootPath)

	require.NoError(t, rqClient.Start(t.Context()))

	t.Run("Upload error", func(t *testing.T) {
		errorChan := make(chan int, failNumber)
		successChan := make(chan string, 1)

		observer.FnOnError = func(ctx context.Context, fileName string, err error, attempt int) {
			t.Logf("Custom observer: upload error for file: %s, attempt: %d, error: %v", fileName, attempt, err)
			select {
			case errorChan <- attempt:

			case <-time.After(time.Second * 5):
				t.Fatal("failed to send to errorChan, timeout")
			}
		}

		observer.FnOnCompleted = func(ctx context.Context, fileName, downloadURL string) {
			t.Logf("Custom observer: upload completed for file: %s: %s", fileName, downloadURL)
			select {
			case successChan <- downloadURL:

			case <-time.After(time.Second * 5):
				t.Fatal("failed to send to successChan, timeout")
			}
		}

		defer func() {
			observer.FnOnError = nil
			observer.FnOnCompleted = nil
		}()

		const testFile = "error_test.png"
		testContent := []byte("error test content")
		require.NoError(t, os.WriteFile(filepath.Join(failingClient.RootPath, testFile), testContent, 0o644))

		err := rqClient.Push(t.Context(), &uploadWorkerArgs{
			ContentType: "image/png",
			FileName:    testFile,
			Source:      uploadSourceFile,
			Path:        []byte(testFile),
		})
		require.NoError(t, err)

		for i := range failNumber {
			select {
			case attempt := <-errorChan:
				t.Logf("Received error callback for attempt: %d", attempt)
				require.Equal(t, i+1, attempt)

			case <-time.After(time.Second * 10):
				t.Fatal("failed to receive error callback, timeout")

			case <-t.Context().Done():
				t.Fatal("failed to receive error callback, context done")
			}
		}

		t.Log("All error callbacks received, waiting for success callback...")
		select {
		case downloadURL := <-successChan:
			t.Logf("Received success callback, download URL: %s", downloadURL)
			require.Equal(t, "download://"+testFile, downloadURL)

		case <-time.After(time.Second * 10):
			t.Fatal("failed to receive success callback, timeout")

		case <-t.Context().Done():
			t.Fatal("failed to receive success callback, context done")
		}

		select {
		case data := <-failingClient.Data:
			t.Logf("Received uploaded data: %s", string(data))
			require.Equal(t, testContent, data)

		case <-time.After(time.Second * 5):
			t.Fatal("failed to receive uploaded data, timeout")

		case <-t.Context().Done():
			t.Fatal("failed to receive uploaded data, context done")
		}
	})

	require.NoError(t, rqClient.Close(t.Context()))
}
