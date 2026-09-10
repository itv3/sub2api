//go:build unit && astra

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Astra 不是当前 Codex CLI 0.151 的仿真范围；该文件仅在下一次明确启用 Astra
// 画像时，通过 `go test -tags='unit astra'` 显式执行。

func TestNormalizeOpenAIResponsesReasoningMode_AstraPreservesBody(t *testing.T) {
	// GPT-6 Astra 保留官方 reasoning.mode 与 reasoning.effort 各自原样：
	// 不删 mode、缺失 effort 也不补 max。非 Astra 的旧兼容行为不受影响。
	tests := []struct {
		name string
		body string
	}{
		{name: "pro + max preserved", body: `{"model":"gpt-6-astra","reasoning":{"mode":"pro","effort":"max"}}`},
		{name: "standard + max preserved", body: `{"model":"gpt-6-astra","reasoning":{"mode":"standard","effort":"max"}}`},
		{name: "missing mode + max preserved", body: `{"model":"gpt-6-astra","reasoning":{"effort":"max"}}`},
		{name: "pro + explicit high preserved", body: `{"model":"gpt-6-astra","reasoning":{"mode":"pro","effort":"high"}}`},
		{name: "pro without effort does not inject max", body: `{"model":"gpt-6-astra","reasoning":{"mode":"pro"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, changed, err := normalizeOpenAIResponsesReasoningMode([]byte(tt.body))
			require.NoError(t, err)
			require.False(t, changed)
			require.JSONEq(t, tt.body, string(normalized))
		})
	}
}

func TestNormalizeOpenAIPassthroughOAuthBody_AstraPreservesReasoningMode(t *testing.T) {
	body := []byte(`{"model":"gpt-6-astra","reasoning":{"mode":"pro","effort":"max"}}`)

	normalized, _, err := normalizeOpenAIPassthroughOAuthBody(body, false)
	require.NoError(t, err)
	require.Equal(t, "pro", gjson.GetBytes(normalized, "reasoning.mode").String())
	require.Equal(t, "max", gjson.GetBytes(normalized, "reasoning.effort").String())
}

func TestNormalizeOpenAIResponsesWebSocketCompatibilityBody_AstraPreservesReasoningMode(t *testing.T) {
	body := []byte(`{"type":"response.create","model":"gpt-6-astra","reasoning":{"mode":"pro","effort":"max"}}`)
	for _, accountType := range []string{AccountTypeOAuth, AccountTypeSetupToken} {
		normalized, _, err := normalizeOpenAIResponsesWebSocketCompatibilityBody(body, &Account{Platform: PlatformOpenAI, Type: accountType}, false)
		require.NoError(t, err)
		require.Equal(t, "pro", gjson.GetBytes(normalized, "reasoning.mode").String())
		require.Equal(t, "max", gjson.GetBytes(normalized, "reasoning.effort").String())
	}
}
