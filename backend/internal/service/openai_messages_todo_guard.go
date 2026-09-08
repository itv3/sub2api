package service

import (
	"encoding/json"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
)

const (
	openAICompatClaudeCodeTodoGuardMarker = "<sub2api-claude-code-todo-guard>"
	openAICompatClaudeCodeTodoGuardText   = openAICompatClaudeCodeTodoGuardMarker + "\nWhen using Claude Code todo or task tracking tools, keep the visible task list consistent. Do not send final or summary text while any item remains in_progress. Before finishing, asking the user to choose, or reporting a blocker, update the todo list so completed work is completed and deferred work is pending/open; leave an item in_progress only when active work will continue in the same turn.\n</sub2api-claude-code-todo-guard>"
)

func appendOpenAICompatClaudeCodeTodoGuard(req *apicompat.ResponsesRequest) bool {
	if req == nil || len(req.Input) == 0 {
		return false
	}

	var items []apicompat.ResponsesInputItem
	if err := json.Unmarshal(req.Input, &items); err != nil {
		return false
	}
	if len(items) == 0 || responsesInputItemsContainText(items, openAICompatClaudeCodeTodoGuardMarker) {
		return false
	}

	content, err := json.Marshal([]apicompat.ResponsesContentPart{{
		Type: "input_text",
		Text: openAICompatClaudeCodeTodoGuardText,
	}})
	if err != nil {
		return false
	}

	guard := apicompat.ResponsesInputItem{
		Type:    "message",
		Role:    "developer",
		Content: content,
	}

	insertAt := 0
	for insertAt < len(items) && items[insertAt].Type == "message" && items[insertAt].Role == "developer" {
		insertAt++
	}

	items = append(items, apicompat.ResponsesInputItem{})
	copy(items[insertAt+1:], items[insertAt:])
	items[insertAt] = guard

	input, err := json.Marshal(items)
	if err != nil {
		return false
	}
	req.Input = input
	return true
}

func appendOpenAICompatClaudeCodeTodoGuardToRequestBody(reqBody map[string]any) bool {
	if reqBody == nil {
		return false
	}

	input, ok := reqBody["input"].([]any)
	if !ok || len(input) == 0 || inputContainsText(input, openAICompatClaudeCodeTodoGuardMarker) {
		return false
	}

	guard := map[string]any{
		"type": "message",
		"role": "developer",
		"content": []any{
			map[string]any{
				"type": "input_text",
				"text": openAICompatClaudeCodeTodoGuardText,
			},
		},
	}

	insertAt := 0
	for insertAt < len(input) {
		item, ok := input[insertAt].(map[string]any)
		if !ok || strings.TrimSpace(firstNonEmptyString(item["type"])) != "message" || strings.TrimSpace(firstNonEmptyString(item["role"])) != "developer" {
			break
		}
		insertAt++
	}

	input = append(input, nil)
	copy(input[insertAt+1:], input[insertAt:])
	input[insertAt] = guard
	reqBody["input"] = input
	return true
}

func responsesInputItemsContainText(items []apicompat.ResponsesInputItem, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	for _, item := range items {
		if strings.Contains(string(item.Content), needle) {
			return true
		}
	}
	return false
}

// inputContainsText 检查 needle 是否出现在各 input 项经 json.Marshal 编码后的文本中。
// json.Marshal 默认做 HTML 转义：'<'、'>'、'&' 与控制字符永远不会原样出现在编码结果里，
// 含这些字符的 needle（包括 openAICompatClaudeCodeTodoGuardMarker）不可能命中，无需逐项
// 编码——逐项编码一个 12 MB 的 input 要再复制两遍正文（docs/bug.md 6.4 第 3 点）。
func inputContainsText(input []any, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" || jsonMarshalNeverEmits(needle) {
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

// jsonMarshalNeverEmits 判断 needle 是否含有 json.Marshal（默认 HTML 转义）绝不会原样输出
// 的字节：'<'、'>'、'&' 会被写成 \u003c、\u003e、\u0026，控制字符会被写成 \n、\u00XX 等。
func jsonMarshalNeverEmits(needle string) bool {
	for i := 0; i < len(needle); i++ {
		switch c := needle[i]; {
		case c == '<', c == '>', c == '&', c < 0x20:
			return true
		}
	}
	return false
}
