// SPDX-License-Identifier: ice License 1.0

package cdn

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/imroc/req/v3"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type (
	Metadata struct {
		Map map[string]string `json:"map"`
	}
	Client interface {
		// SubmitFileUploadJob uploads data to the CDN asynchronously via a background worker.
		SubmitFileUploadJob(ctx context.Context, data []byte, contentType, fileName string, m *Metadata) error

		// FileUpload uploads a file to the CDN synchronously calling the CDN API directly.
		FileUpload(ctx context.Context, data io.Reader, contentType, fileName string) (string, error)

		// HealthCheck checks the health of the CDN service.
		HealthCheck(ctx context.Context) error

		// Observer returns the state observer, if any.
		Observer() StateObserver
	}
	StateObserver interface {
		// OnUploadCompleted is called when a file upload is completed successfully.
		OnUploadCompleted(ctx context.Context, fileName, downloadURL string, m *Metadata)

		// OnUploadError is called when a file upload fails with an error and provides the attempt number.
		OnUploadError(ctx context.Context, fileName string, err error, attempt, maxAttempts int, m *Metadata)
	}
	Config struct {
		AccessKey     string        `yaml:"accessKey"`
		URLUpload     string        `yaml:"urlUpload"`
		URLDownload   string        `yaml:"urlDownload"`
		JobMaxTimeout time.Duration `yaml:"maxJobTimeout"`
	}
	Option func(*client)

	client struct {
		RqClient            riverqueue.Client
		StateObserver       StateObserver
		Config              *Config
		HealthCheckPassedAt atomic.Int64
		HealthCheckMux      sync.RWMutex
	}
)

const (
	defaultJobTimeout = 10 * time.Minute
	maxUploadRetries  = 20
)

func WithObserver(observer StateObserver) Option {
	return func(c *client) {
		c.StateObserver = observer
	}
}

func New(ctx context.Context, config *Config, rqClient riverqueue.Client, opts ...Option) Client {
	client := newClient(ctx, config, rqClient, opts...)
	if err := client.HealthCheck(ctx); err != nil {
		log.Panic(err, "failed to create CDN client")
	}
	return client
}

func newClient(_ context.Context, config *Config, rqClient riverqueue.Client, opts ...Option) *client {
	var cdnClient = &client{
		Config:   config,
		RqClient: rqClient,
	}

	for _, opt := range opts {
		opt(cdnClient)
	}

	riverqueue.RegisterWorker(rqClient.Register(), &uploadWorker{
		Client:     cdnClient,
		JobTimeout: config.JobMaxTimeout,
	})
	return cdnClient
}

func (c *client) Observer() StateObserver {
	return c.StateObserver
}

func (c *client) cdnUploadURL(filename string) string {
	if strings.HasPrefix(filename, c.Config.URLUpload) {
		return filename
	}
	u, _ := url.JoinPath(c.Config.URLUpload, filename)
	return u
}

func (c *client) FileUpload(ctx context.Context, data io.Reader, contentType, fileName string) (target string, err error) {
	fileData, err := io.ReadAll(data)
	if err != nil {
		return "", fmt.Errorf("failed to read file data for %v: %w", fileName, err)
	}

	target, err = c.doCdnUpload(ctx, contentType, fileName, fileData)
	if err != nil {
		return "", fmt.Errorf("error uploading file %v: %w", fileName, err)
	}

	return target, nil
}

func (c *client) doCdnUpload(ctx context.Context, contentType, fileName string, fileData []byte) (string, error) {
	resp, err := c.cdnReq(ctx).
		SetHeader("Content-Type", contentType).
		SetBodyBytes(fileData).
		Put(c.cdnUploadURL(fileName))
	if err != nil {
		return "", fmt.Errorf("upload request failed: %w", err)
	}

	if resp.IsSuccessState() {
		return c.CdnDownloadURL(fileName), nil
	}

	body, err := resp.ToString()
	log.Warn(fmt.Sprintf("failed to upload file %v to cdn, status code: %d, content type: %s, body: %s", fileName, resp.GetStatusCode(), contentType, body))

	return "", fmt.Errorf("upload failed with status %d", resp.GetStatusCode())
}

func (c *client) cdnReq(ctx context.Context) *req.Request {
	return req.
		SetContext(ctx).
		SetRetryBackoffInterval(300*time.Millisecond, 3*time.Second).
		SetRetryHook(func(resp *req.Response, err error) {
			var body string
			if resp != nil {
				body, _ = resp.ToString()
			}
			switch {
			case err != nil:
				log.Error(err, fmt.Sprintf("failed to upload file to cdn, body: %s", body))
			case resp.GetStatusCode() == http.StatusTooManyRequests:
				log.Warn(fmt.Sprintf("rate limited when uploading file to cdn, status: %d, body: %s", resp.GetStatusCode(), body))
			case resp.GetStatusCode() >= http.StatusInternalServerError:
				log.Error(fmt.Errorf("server error %d", resp.GetStatusCode()), fmt.Sprintf("failed to upload file to cdn, body: %s", body))
			}
		}).
		SetRetryCount(maxUploadRetries).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || resp.GetStatusCode() == http.StatusTooManyRequests || resp.GetStatusCode() >= http.StatusInternalServerError
		}).
		SetHeader("AccessKey", c.Config.AccessKey)
}

func (c *client) HealthCheck(ctx context.Context) error {
	locked := c.HealthCheckMux.TryLock()
	if hPassed := time.Unix(c.HealthCheckPassedAt.Load(), 0); !locked || time.Since(hPassed) <= 30*time.Second {
		return nil
	}
	defer func() {
		if locked {
			c.HealthCheckMux.Unlock()
		}
	}()

	bootstrapCtx, cancelBootstrap := context.WithTimeout(ctx, 30*time.Second)
	defer cancelBootstrap()

	resp, err := c.cdnReq(bootstrapCtx).Delete(c.cdnUploadURL(uuid.NewString() + ".jpg"))
	if err != nil {
		return fmt.Errorf("healthcheck request failed: %w", err)
	}

	if resp.GetStatusCode() != http.StatusNotFound {
		return fmt.Errorf("healthcheck failed: expected status %d, got %d", http.StatusNotFound, resp.GetStatusCode())
	}

	c.HealthCheckPassedAt.Store(time.Now().Unix())
	return nil
}

func (c *client) SubmitFileUploadJob(ctx context.Context, data []byte, contentType, fileName string, m *Metadata) error {
	err := c.RqClient.Push(ctx, &uploadWorkerArgs{
		ContentType: contentType,
		FileName:    fileName,
		Data:        data,
		Metadata:    m,
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue cdn upload job for file %v: %w", fileName, err)
	}
	return nil
}

func (c *client) CdnDownloadURL(filename string) string {
	if strings.HasPrefix(filename, c.Config.URLDownload) {
		return filename
	}
	u, _ := url.JoinPath(c.Config.URLDownload, filename)

	return u
}

func (m *Metadata) Set(key, value string) *Metadata {
	if m.Map == nil {
		m.Map = make(map[string]string)
	}
	m.Map[key] = value
	return m
}

func (m *Metadata) Get(key string) string {
	if m.Map == nil {
		return ""
	}
	return m.Map[key]
}
