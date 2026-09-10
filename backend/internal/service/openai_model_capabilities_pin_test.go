//go:build unit

package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// capabilityPinManifestUpstream 的账号清单只列出 gpt-5.6-luna（visibility=list）：
// 内置能力表判 gpt-5.6-terra 为 Lite，账号清单接管后 terra 变为“已知不支持”，
// 两者相反，正好用来观察同一请求内的判定是否被钉住。
type capabilityPinManifestUpstream struct{}

func (capabilityPinManifestUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(
			`{"models":[{"slug":"gpt-5.6-luna","visibility":"list","use_responses_lite":true,"supports_parallel_tool_calls":true}]}`,
		)),
	}, nil
}

func (u capabilityPinManifestUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxyURL, accountID, concurrency)
}

func TestOpenAIModelCapabilityPinnedWithinRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: capabilityPinManifestUpstream{}}
	account := &Account{
		ID: 9101, Name: "capability-pin", Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Concurrency: 1, Status: StatusActive, Schedulable: true, RateMultiplier: f64p(1),
		Credentials: map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-account"},
	}
	body := []byte(`{"model":"gpt-5.6-terra","stream":true,"input":[{"type":"message","role":"user","content":"hello"}]}`)

	ctx := context.Background()
	require.NoError(t, svc.ensureOpenAIModelCapability(ctx, account, body))
	ctx = svc.bindOpenAIResponsesLiteCapability(ctx, account, body)
	require.True(t, openAIModelCapabilitiesFromContext(ctx).UseResponsesLite, "ensure 之后按内置能力表判 Lite")

	// 后台刷新落地后，不带上下文的解析会翻转为非 Lite。
	require.Eventually(t, func() bool {
		return !svc.resolveOpenAIModelCapabilities(account, body).UseResponsesLite
	}, 2*time.Second, 10*time.Millisecond)

	// 同一请求内再次绑定与入站归一化仍沿用首次查表结果。
	rebound := svc.bindOpenAIResponsesLiteCapability(ctx, account, body)
	require.True(t, openAIModelCapabilitiesFromContext(rebound).UseResponsesLite)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	require.True(t, svc.normalizeOpenAIResponsesLiteIngressHeader(ctx, c, account, body))
	require.Equal(t, "true", c.Request.Header.Get(responsesLiteHeader))

	// hosted tool 的按 body 修正仍按当时的 body 生效，不受钉住影响。
	hosted := []byte(`{"model":"gpt-5.6-terra","stream":true,"tools":[{"type":"web_search"}],"input":[{"type":"message","role":"user","content":"hello"}]}`)
	require.False(t, openAIModelCapabilitiesFromContext(svc.bindOpenAIResponsesLiteCapability(ctx, account, hosted)).UseResponsesLite)

	// 未钉住的新上下文按当前快照解析，得到刷新后的判定。
	fresh := svc.bindOpenAIResponsesLiteCapability(context.Background(), account, body)
	require.False(t, openAIModelCapabilitiesFromContext(fresh).UseResponsesLite)
}
