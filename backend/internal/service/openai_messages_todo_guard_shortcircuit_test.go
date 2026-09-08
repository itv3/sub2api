package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// legacyInputContainsText 是加入短路之前的实现：逐项 json.Marshal 后做子串匹配。
func legacyInputContainsText(input []any, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	for _, item := range input {
		b, err := json.Marshal(item)
		if err == nil && strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}

func TestInputContainsTextShortCircuitMatchesMarshalLoop(t *testing.T) {
	items := []any{
		map[string]any{"type": "message", "content": []any{map[string]any{"type": "input_text", "text": openAICompatClaudeCodeTodoGuardMarker + " hello"}}},
		map[string]any{"text": "\\u003csub2api-claude-code-todo-guard\\u003e"},
		"plain <x> & y",
		json.Number("123"),
		map[string]any{"<k>": "v"},
		map[string]any{"a": "b&c", "b": "tab\there", "c": "line\nbreak", "d": "quote\"q", "e": "back\\slash"},
		true, nil, []any{"<", ">", "&"},
	}
	needles := []string{
		openAICompatClaudeCodeTodoGuardMarker, "<", ">", "&", "u003c", "\\u003c", "sub2api-claude-code-todo-guard", "plain", "123",
		"\t", "tab", "here", "\\t", "b&c", "b\\u0026c", " ", "", "quote", "\"q", "\\\"q", "back\\slash", "back\\\\slash", "true", "null",
		"line\nbreak", "\\n", "x> &", "hello", "input_text", "content",
	}
	for _, needle := range needles {
		require.Equal(t, legacyInputContainsText(items, needle), inputContainsText(items, needle), "needle=%q", needle)
	}
	// json.Marshal 默认 HTML 转义：守卫标记含 '<' '>'，逐项编码后永远匹配不到，短路必须与之一致。
	require.False(t, legacyInputContainsText(items, openAICompatClaudeCodeTodoGuardMarker))
	require.False(t, inputContainsText(items, openAICompatClaudeCodeTodoGuardMarker))
	require.True(t, jsonMarshalNeverEmits(openAICompatClaudeCodeTodoGuardMarker))
}
