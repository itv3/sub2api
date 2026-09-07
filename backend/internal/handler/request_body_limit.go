package handler

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync/atomic"

	appconfig "github.com/Wei-Shaw/sub2api/internal/config"
	pkghttputil "github.com/Wei-Shaw/sub2api/internal/pkg/httputil"
)

const (
	defaultRequestMemoryAmplification = 5.0
	defaultRequestMemoryFixedBytes    = 8 << 20
	defaultRequestMemoryRetryAfter    = 2
)

// requestMemoryAdmission 是 Responses 正文处理的进程级加权准入器。
// 它只保存计数和固定大小的统计，不保存请求正文；正文读取前先占用预算，
// 请求生命周期结束后释放，避免并发排队请求在获得账号槽位前堆积大对象。
type requestMemoryAdmission struct {
	capacityBytes int64
	usedBytes     atomic.Int64
	accepted      atomic.Uint64
	rejected      atomic.Uint64
	tooLarge      atomic.Uint64
}

type requestMemoryReservation struct {
	admission *requestMemoryAdmission
	bytes     int64
	released  atomic.Bool
}

func newRequestMemoryAdmission(cfg *appconfig.Config) *requestMemoryAdmission {
	if cfg == nil || cfg.Gateway.RequestMemoryBudgetBytes <= 0 {
		return nil
	}
	return &requestMemoryAdmission{capacityBytes: cfg.Gateway.RequestMemoryBudgetBytes}
}

func (a *requestMemoryAdmission) tryAcquire(bytes int64) (*requestMemoryReservation, bool) {
	if a == nil || a.capacityBytes <= 0 || bytes <= 0 {
		return &requestMemoryReservation{}, true
	}
	for {
		used := a.usedBytes.Load()
		if used > a.capacityBytes-bytes {
			a.rejected.Add(1)
			return nil, false
		}
		if a.usedBytes.CompareAndSwap(used, used+bytes) {
			a.accepted.Add(1)
			return &requestMemoryReservation{admission: a, bytes: bytes}, true
		}
	}
}

func (r *requestMemoryReservation) release() {
	if r == nil || r.admission == nil || r.released.Swap(true) {
		return
	}
	r.admission.usedBytes.Add(-r.bytes)
}

func (a *requestMemoryAdmission) stats() (used, capacity int64, accepted, rejected, tooLarge uint64) {
	if a == nil {
		return 0, 0, 0, 0, 0
	}
	return a.usedBytes.Load(), a.capacityBytes, a.accepted.Load(), a.rejected.Load(), a.tooLarge.Load()
}

// requestMemoryAdmissionConfig 从配置计算单请求硬上限和加权预算。
func requestMemoryAdmissionConfig(cfg *appconfig.Config) (maxRequest, fixed int64, amplification float64) {
	if cfg == nil {
		return 0, defaultRequestMemoryFixedBytes, defaultRequestMemoryAmplification
	}
	maxRequest = cfg.Gateway.RequestMemoryMaxRequestBytes
	if maxRequest <= 0 {
		maxRequest = cfg.Gateway.TextMaxBodySize
	}
	if maxRequest <= 0 {
		maxRequest = cfg.Gateway.MaxBodySize
	}
	fixed = cfg.Gateway.RequestMemoryFixedBytes
	if fixed < 0 {
		fixed = 0
	}
	if fixed == 0 {
		fixed = defaultRequestMemoryFixedBytes
	}
	amplification = cfg.Gateway.RequestMemoryAmplification
	if amplification < 1 {
		amplification = defaultRequestMemoryAmplification
	}
	return maxRequest, fixed, amplification
}

func requestMemoryWeight(req *http.Request, cfg *appconfig.Config) (weight int64, tooLarge bool) {
	maxRequest, fixed, amplification := requestMemoryAdmissionConfig(cfg)
	if req == nil {
		return fixed, false
	}
	contentLength := req.ContentLength
	encoding := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding")))
	// 压缩正文的 Content-Length 只代表压缩后的大小，chunked 请求没有长度；
	// 两者都按单请求上限预留，不能让解压后的正文绕过准入。
	if contentLength >= 0 && (encoding == "" || encoding == "identity") {
		if maxRequest > 0 && contentLength > maxRequest {
			return 0, true
		}
	} else {
		contentLength = maxRequest
	}
	if contentLength <= 0 {
		contentLength = 1 << 20
	}
	if maxRequest > 0 && contentLength > maxRequest {
		return 0, true
	}
	calculated := float64(contentLength)*amplification + float64(fixed)
	if calculated >= float64(math.MaxInt64) {
		return math.MaxInt64, false
	}
	return int64(math.Ceil(calculated)), false
}

func extractMaxBytesError(err error) (*http.MaxBytesError, bool) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return maxErr, true
	}
	return nil, false
}

func formatBodyLimit(limit int64) string {
	const mb = 1024 * 1024
	if limit >= mb {
		return fmt.Sprintf("%dMB", limit/mb)
	}
	return fmt.Sprintf("%dB", limit)
}

func buildBodyTooLargeMessage(limit int64) string {
	return fmt.Sprintf("Request body too large, limit is %s", formatBodyLimit(limit))
}

func readLenientJSONRequestBodyWithPrealloc(req *http.Request, cfg *appconfig.Config) ([]byte, error) {
	return pkghttputil.ReadLenientJSONRequestBodyWithPrealloc(req, gatewayMaxBodySize(cfg))
}

func readResponsesJSONRequestBodyWithPrealloc(req *http.Request, cfg *appconfig.Config) ([]byte, error) {
	limit := gatewayMaxBodySize(cfg)
	if maxRequest, _, _ := requestMemoryAdmissionConfig(cfg); maxRequest > 0 &&
		(limit <= 0 || maxRequest < limit) {
		limit = maxRequest
	}
	return pkghttputil.ReadLenientJSONRequestBodyWithPrealloc(req, limit)
}

func gatewayMaxBodySize(cfg *appconfig.Config) int64 {
	if cfg == nil {
		return 0
	}
	return cfg.Gateway.MaxBodySize
}
