// SPDX-License-Identifier: ice License 1.0

package ion_indexer

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	stdlibtime "time"

	"github.com/goccy/go-json"
	"github.com/imroc/req/v3"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"

	appcfg "github.com/ice-blockchain/wintr/config"
	"github.com/ice-blockchain/wintr/log"
)

func init() {
	req.DefaultClient().GetClient().Transport = &http2.Transport{}
	req.DefaultClient().GetClient().Timeout = 30 * stdlibtime.Second
	req.DefaultClient().SetJsonMarshal(json.Marshal)
	req.DefaultClient().SetJsonUnmarshal(json.Unmarshal)
}

func New(isTestnet bool) Indexer {
	var cfg config
	appcfg.MustLoadFromKey(applicationYamlKey, &cfg)
	if cfg.ION == "" {
		log.Panic(errors.Errorf("indexer>ion not configured"))
	}
	i := &indexer{
		testnet: isTestnet,
		config:  &cfg,
	}
	return i
}

func indexerReq[T any](ctx context.Context, i *indexer, relativeUrl string, params map[string]string, unmarshal func([]byte) ([]T, bool, error)) ([]T, uint, error) {
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}

	if _, hasLimit := params["limit"]; !hasLimit {
		params["limit"] = fmt.Sprintf("%v", defaultIndexerReqLimit)
	}

	if resp, err := req.C().SetBaseURL(i.config.ION).R().
		SetContext(ctx).
		SetRetryCount(3).
		SetRetryInterval(func(resp *req.Response, attempt int) stdlibtime.Duration {
			return 1 * stdlibtime.Second
		}).
		SetRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to call indexer %v %v, retrying...", i.config.ION, relativeUrl))
			} else {
				log.Error(errors.Errorf("failed to call indexer %v, relativeUrl:%v with status code:%v, retrying...", i.config.ION, relativeUrl, resp.GetStatusCode()))
			}
		}).
		SetRetryCondition(func(resp *req.Response, err error) bool {
			return err != nil || resp.GetStatusCode() != http.StatusOK
		}).
		SetQueryParams(params).
		SetHeader("Accept", "application/json").
		SetHeader("Cache-Control", "no-cache, no-store, must-revalidate").
		SetHeader("Pragma", "no-cache").
		SetHeader("Expires", "0").
		Get(relativeUrl); err != nil {
		return nil, 0, errors.Wrapf(err, "failed to call indexer %v %v", i.config.ION, relativeUrl)

	} else if statusCode := resp.GetStatusCode(); statusCode != http.StatusOK {
		return nil, 0, errors.Errorf("failed to check indexer %v %v with status code:%v", i.config.ION, relativeUrl, statusCode)
	} else if data, err2 := resp.ToBytes(); err2 != nil {
		return nil, 0, errors.Wrapf(err2, "failed to read body of indexer %v %v response", i.config.ION, relativeUrl)
	} else {
		res, continuePagination, err3 := unmarshal(data)
		if err3 != nil {
			return nil, 0, errors.Wrapf(err3, "failed to unmarshal response of indexer %v %v", i.config.ION, relativeUrl)
		}
		offset := 0
		if off, hasOffset := params["offset"]; hasOffset {
			offset, _ = strconv.Atoi(off)
		}
		totalOffset := uint(offset + len(res))
		if continuePagination {
			if limit, hasLimit := params["limit"]; hasLimit {
				lim, _ := strconv.Atoi(limit)
				offset += int(lim)
			} else {
				offset += int(defaultIndexerReqLimit)
			}
			params["offset"] = strconv.Itoa(offset)
			nextPage, newOff, err := indexerReq[T](ctx, i, relativeUrl, params, unmarshal)
			if err != nil {
				return nil, 0, errors.Wrapf(err, "failed to load page of %v %v (offset %v)", i.config.ION, relativeUrl, offset)
			}
			res = append(res, nextPage...)
			totalOffset += newOff
		}
		return res, totalOffset, nil
	}
}
