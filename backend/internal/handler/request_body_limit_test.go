package handler

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRequestBodyLimitTooLarge(t *testing.T) {
	gin.SetMode(gin.TestMode)

	limit := int64(16)
	router := gin.New()
	router.Use(middleware.RequestBodyLimit(limit))
	router.POST("/test", func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			if maxErr, ok := extractMaxBytesError(err); ok {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{
					"error": buildBodyTooLargeMessage(maxErr.Limit),
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "read_failed",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	payload := bytes.Repeat([]byte("a"), int(limit+1))
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)
	require.Contains(t, recorder.Body.String(), buildBodyTooLargeMessage(limit))
}

func TestRequestMemoryAdmissionReservesBeforeReadAndReleases(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.RequestMemoryBudgetBytes = 128
	cfg.Gateway.RequestMemoryMaxRequestBytes = 32
	cfg.Gateway.RequestMemoryAmplification = 2
	cfg.Gateway.RequestMemoryFixedBytes = 8
	admission := newRequestMemoryAdmission(cfg)

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte("{}")))
	req.ContentLength = 20
	weight, tooLarge := requestMemoryWeight(req, cfg)
	require.False(t, tooLarge)
	require.Equal(t, int64(48), weight)

	first, ok := admission.tryAcquire(weight)
	require.True(t, ok)
	second, ok := admission.tryAcquire(weight)
	require.True(t, ok)
	third, ok := admission.tryAcquire(weight)
	require.False(t, ok)
	require.Nil(t, third)
	first.release()
	third, ok = admission.tryAcquire(weight)
	require.True(t, ok)
	second.release()
	third.release()
	used, capacity, accepted, rejected, _ := admission.stats()
	require.Zero(t, used)
	require.Equal(t, int64(128), capacity)
	require.Equal(t, uint64(3), accepted)
	require.Equal(t, uint64(1), rejected)
}

func TestRequestMemoryAdmissionRejectsOversizedAndCompressedUnknown(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.RequestMemoryBudgetBytes = 1024
	cfg.Gateway.RequestMemoryMaxRequestBytes = 32
	cfg.Gateway.RequestMemoryAmplification = 2
	cfg.Gateway.RequestMemoryFixedBytes = 8

	tooLargeReq := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	tooLargeReq.ContentLength = 33
	_, tooLarge := requestMemoryWeight(tooLargeReq, cfg)
	require.True(t, tooLarge)

	chunkedReq := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	chunkedReq.ContentLength = -1
	chunkedReq.Header.Set("Content-Encoding", "gzip")
	weight, tooLarge := requestMemoryWeight(chunkedReq, cfg)
	require.False(t, tooLarge)
	require.Equal(t, int64(72), weight)
}
