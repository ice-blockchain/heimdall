// SPDX-License-Identifier: ice License 1.0

package cdn

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type (
	uploadSource     int
	uploadWorkerArgs struct {
		ContentType string
		FileName    string
		Path        []byte // Can be either file path or data depending on `Source`.
		Source      uploadSource
		Metadata    *Metadata
	}
	uploadWorker struct {
		riverqueue.WorkerDefaults[uploadWorkerArgs]
		Client        Client
		RootPath      string
		JobTimeout    time.Duration
		JobRetryAfter time.Duration
	}
	uploadWorkerJob = riverqueue.Job[uploadWorkerArgs]
)

const (
	uploadSourceFile uploadSource = iota + 1
	uploadSourceData
)

func (uploadWorkerArgs) Kind() string {
	return "ta_cdn_upload_worker_args"
}

func (w *uploadWorker) Timeout(job *uploadWorkerJob) time.Duration {
	return cmp.Or(w.JobTimeout, defaultJobTimeout)
}

func (w *uploadWorker) NextRetry(job *uploadWorkerJob) time.Time {
	if w.JobRetryAfter > 0 {
		return time.Now().Add(w.JobRetryAfter)
	}
	return time.Time{} // Use default backoff strategy.
}

func (w *uploadWorker) Work(ctx context.Context, job *uploadWorkerJob) (err error) {
	defer func() {
		log.Debug(fmt.Sprintf("CDN upload worker finished for file: %s with error: %v, attempt: %d", job.Args.FileName, err, job.Attempt))
		if o := w.Client.Observer(); err != nil && o != nil {
			o.OnUploadError(ctx, job.Args.FileName, err, job.Attempt, job.MaxAttempts, job.Args.Metadata)
		}
	}()

	log.Debug(fmt.Sprintf("CDN upload worker started for file: %s, attempt: %d", job.Args.FileName, job.Attempt))

	var r io.Reader
	switch job.Args.Source {
	case uploadSourceData:
		r = bytes.NewReader(job.Args.Path)

	case uploadSourceFile:
		f, err := os.OpenInRoot(w.RootPath, string(job.Args.Path))
		if err != nil {
			return fmt.Errorf("failed to open file %v: %w", string(job.Args.Path), err)
		}
		r = f
		defer f.Close()

	default:
		log.Warn(fmt.Sprintf("unknown upload source for file: %s, attempt: %d", job.Args.FileName, job.Attempt))
		return nil // Just skip unknown sources.
	}

	downloadURL, uploadErr := w.Client.FileUpload(ctx, r, job.Args.ContentType, job.Args.FileName)
	if uploadErr != nil {
		return fmt.Errorf("failed to upload file %v to CDN: %w", job.Args.FileName, uploadErr)
	}

	if o := w.Client.Observer(); o != nil {
		o.OnUploadCompleted(ctx, job.Args.FileName, downloadURL, job.Args.Metadata)
	}

	return nil
}
