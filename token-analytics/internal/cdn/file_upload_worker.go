// SPDX-License-Identifier: ice License 1.0

package cdn

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/ice-blockchain/wintr/log"
	"github.com/ice-blockchain/wintr/riverqueue"
)

type (
	uploadWorkerArgs struct {
		ContentType string
		FileName    string
		Data        []byte
		Metadata    *Metadata
	}
	uploadWorker struct {
		riverqueue.WorkerDefaults[uploadWorkerArgs]
		Client        Client
		JobTimeout    time.Duration
		JobRetryAfter time.Duration
	}
	uploadWorkerJob = riverqueue.Job[uploadWorkerArgs]
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

	downloadURL, uploadErr := w.Client.FileUpload(ctx, bytes.NewReader(job.Args.Data), job.Args.ContentType, job.Args.FileName)
	if uploadErr != nil {
		return fmt.Errorf("failed to upload file %v to CDN: %w", job.Args.FileName, uploadErr)
	}

	if o := w.Client.Observer(); o != nil {
		o.OnUploadCompleted(ctx, job.Args.FileName, downloadURL, job.Args.Metadata)
	}

	return nil
}
