package service

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/tidwall/gjson"
)

var openAIResponsesLiteHostedToolTypes = map[string]struct{}{
	"image_generation":     {},
	"web_search":           {},
	"web_search_preview":   {},
	"x_search":             {},
	"file_search":          {},
	"code_interpreter":     {},
	"computer_use_preview": {},
}

// Responses 的 hosted 工具在 input 历史中使用独立的 call 类型。这里必须
// 使用显式集合，不能用“所有 *_call”这种宽匹配：Codex 的 custom_tool_call、
// tool_search_call、local_shell_call 和 mcp_tool_call 都是 Lite 可以承载的
// 客户端工具续接，误判会把正常请求切到另一条能力链路并破坏续接画像。
var openAIResponsesLiteHostedToolCallTypes = map[string]struct{}{
	"image_generation_call": {},
	"web_search_call":       {},
	"x_search_call":         {},
	"file_search_call":      {},
	"code_interpreter_call": {},
	"computer_call":         {},
	"computer_call_output":  {},
	"mcp_call":              {},
	"mcp_approval_request":  {},
	"mcp_approval_response": {},
	"mcp_list_tools":        {},
	"mcp_list_tools_output": {},
}

func isOpenAIResponsesLiteHostedToolType(toolType string) bool {
	_, hosted := openAIResponsesLiteHostedToolTypes[strings.TrimSpace(toolType)]
	return hosted
}

func isOpenAIResponsesLiteHostedToolCallType(itemType string) bool {
	_, hosted := openAIResponsesLiteHostedToolCallTypes[strings.TrimSpace(itemType)]
	return hosted
}

// openAIResponsesLiteRequiresFullResponses 判断请求是否声明了 Lite 无法承载的
// hosted tool。仅按顶层 tool type 和明确的 tool_choice/历史调用项判断；名为
// web_search 的普通 function 仍是客户端函数，不应被误当成 hosted tool。
func openAIResponsesLiteRequiresFullResponses(body []byte) bool {
	if len(body) == 0 || !gjson.ValidBytes(body) {
		return false
	}
	var containsHostedType func(gjson.Result) bool
	containsHostedType = func(value gjson.Result) bool {
		if !value.Exists() || !value.IsObject() {
			return false
		}
		if isOpenAIResponsesLiteHostedToolType(value.Get("type").String()) {
			return true
		}
		// namespace/additional_tools 可能携带嵌套工具定义；只沿 tools
		// 字段递归，避免把函数参数 schema 中同名字符串误判为 hosted。
		nestedTools := value.Get("tools")
		if !nestedTools.IsArray() {
			return false
		}
		for _, nested := range nestedTools.Array() {
			if containsHostedType(nested) {
				return true
			}
		}
		return false
	}
	tools := gjson.GetBytes(body, "tools")
	if tools.IsArray() {
		for _, tool := range tools.Array() {
			if containsHostedType(tool) {
				return true
			}
		}
	}
	toolChoice := gjson.GetBytes(body, "tool_choice")
	if containsHostedType(toolChoice) {
		return true
	}
	if toolChoice.Type == gjson.String {
		if isOpenAIResponsesLiteHostedToolType(toolChoice.String()) {
			return true
		}
	}
	input := gjson.GetBytes(body, "input")
	if input.IsArray() {
		for _, item := range input.Array() {
			itemType := strings.TrimSpace(item.Get("type").String())
			if isOpenAIResponsesLiteHostedToolCallType(itemType) {
				return true
			}
		}
	}
	return false
}

type openAIResponsesLiteValidationError struct {
	param   string
	message string
}

func (e *openAIResponsesLiteValidationError) Error() string { return e.message }

func newOpenAIResponsesLiteValidationError(param, format string, args ...any) error {
	return &openAIResponsesLiteValidationError{param: param, message: fmt.Sprintf(format, args...)}
}

// normalizeOpenAIResponsesLiteTools applies the Responses Lite request
// contract: reasoning must cover all turns, and private namespace declarations
// use the input.additional_tools carrier. Other top-level tools must belong to
// the small set accepted by the Lite endpoint; rejecting unsupported hosted
// tools is intentional because silently dropping them would change behavior.
func normalizeOpenAIResponsesLiteTools(reqBody map[string]any) (bool, error) {
	if reqBody == nil {
		return false, nil
	}
	if parallel, exists := reqBody["parallel_tool_calls"]; exists {
		if _, ok := parallel.(bool); !ok {
			return false, newOpenAIResponsesLiteValidationError("parallel_tool_calls", "responses Lite requires parallel_tool_calls to be a boolean")
		}
	}
	if rawReasoning, exists := reqBody["reasoning"]; exists && rawReasoning != nil {
		if _, ok := rawReasoning.(map[string]any); !ok {
			return false, newOpenAIResponsesLiteValidationError("reasoning", "responses Lite requires reasoning to be an object")
		}
	}
	rawTools, exists := reqBody["tools"]
	if !exists || rawTools == nil {
		changed, err := ensureOpenAIResponsesLiteReasoningContext(reqBody)
		if err != nil {
			return false, err
		}
		return ensureOpenAIResponsesLiteParallelToolCalls(reqBody, changed)
	}
	tools, ok := rawTools.([]any)
	if !ok {
		return false, newOpenAIResponsesLiteValidationError("tools", "responses Lite requires tools to be an array")
	}

	topLevelTools := make([]any, 0, len(tools))
	namespaceTools := make([]any, 0, len(tools))
	for index, rawTool := range tools {
		if customTool, ok := rawTool.(string); ok {
			if strings.TrimSpace(customTool) == "" {
				return false, fmt.Errorf("responses Lite custom tool at index %d must not be empty", index)
			}
			topLevelTools = append(topLevelTools, rawTool)
			continue
		}
		tool, ok := rawTool.(map[string]any)
		if !ok {
			return false, fmt.Errorf("responses Lite tool at index %d must be an object", index)
		}
		toolType := strings.TrimSpace(firstNonEmptyString(tool["type"]))
		switch toolType {
		case "function", "custom", "tool_search":
			topLevelTools = append(topLevelTools, rawTool)
		case "namespace":
			namespaceTools = append(namespaceTools, rawTool)
		case "":
			return false, fmt.Errorf("responses Lite tool at index %d is missing type", index)
		default:
			return false, fmt.Errorf("responses Lite does not support top-level tool type %q at index %d", toolType, index)
		}
	}
	if len(namespaceTools) == 0 {
		changed, err := ensureOpenAIResponsesLiteReasoningContext(reqBody)
		if err != nil {
			return false, err
		}
		return ensureOpenAIResponsesLiteParallelToolCalls(reqBody, changed)
	}

	input, err := appendOpenAIResponsesLiteAdditionalTools(reqBody["input"], namespaceTools)
	if err != nil {
		return false, err
	}
	if _, err := ensureOpenAIResponsesLiteReasoningContext(reqBody); err != nil {
		return false, err
	}
	reqBody["input"] = input
	if len(topLevelTools) == 0 {
		delete(reqBody, "tools")
	} else {
		reqBody["tools"] = topLevelTools
	}
	return ensureOpenAIResponsesLiteParallelToolCalls(reqBody, true)
}

func ensureOpenAIResponsesLiteParallelToolCalls(reqBody map[string]any, changed bool) (bool, error) {
	parallel := reqBody["parallel_tool_calls"]
	if !openAIResponsesLiteHasTools(reqBody) {
		return changed, nil
	}
	if parallel == false {
		return changed, nil
	}
	reqBody["parallel_tool_calls"] = false
	return true, nil
}

func openAIResponsesLiteHasTools(reqBody map[string]any) bool {
	if tools, ok := reqBody["tools"].([]any); ok && len(tools) > 0 {
		return true
	}
	input, _ := reqBody["input"].([]any)
	for _, rawItem := range input {
		item, ok := rawItem.(map[string]any)
		if !ok || strings.TrimSpace(firstNonEmptyString(item["type"])) != "additional_tools" {
			continue
		}
		if tools, ok := item["tools"].([]any); ok && len(tools) > 0 {
			return true
		}
	}
	return false
}

func ensureOpenAIResponsesLiteReasoningContext(reqBody map[string]any) (bool, error) {
	rawReasoning, exists := reqBody["reasoning"]
	if !exists || rawReasoning == nil {
		reqBody["reasoning"] = map[string]any{"context": "all_turns"}
		return true, nil
	}
	reasoning, ok := rawReasoning.(map[string]any)
	if !ok {
		return false, newOpenAIResponsesLiteValidationError("reasoning", "responses Lite requires reasoning to be an object")
	}
	if context, ok := reasoning["context"].(string); ok && context == "all_turns" {
		return false, nil
	}
	reasoning["context"] = "all_turns"
	return true, nil
}

func appendOpenAIResponsesLiteAdditionalTools(input any, namespaceTools []any) ([]any, error) {
	var items []any
	switch typed := input.(type) {
	case nil:
		items = make([]any, 0, 1)
	case string:
		items = []any{map[string]any{
			"type":    "message",
			"role":    "user",
			"content": typed,
		}}
	case []any:
		items = typed
	default:
		return nil, fmt.Errorf("responses Lite namespace tools require input to be a string or array")
	}

	var target map[string]any
	var targetTools []any
	var allAdditionalTools []any
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok || strings.TrimSpace(firstNonEmptyString(item["type"])) != "additional_tools" {
			continue
		}
		rawAdditionalTools, exists := item["tools"]
		additionalTools := []any(nil)
		toolsOK := true
		if exists && rawAdditionalTools != nil {
			additionalTools, toolsOK = rawAdditionalTools.([]any)
		}
		if !toolsOK {
			return nil, fmt.Errorf("responses Lite input.additional_tools tools must be an array")
		}
		if target == nil {
			target = item
			targetTools = additionalTools
		}
		allAdditionalTools = append(allAdditionalTools, additionalTools...)
	}

	merged, err := mergeOpenAIResponsesLiteAdditionalTools(allAdditionalTools, namespaceTools)
	if err != nil {
		return nil, err
	}
	newTools := merged[len(allAdditionalTools):]
	if target != nil {
		if len(newTools) > 0 {
			target["tools"] = append(append([]any(nil), targetTools...), newTools...)
		}
		return items, nil
	}

	items = append(items, map[string]any{
		"type":  "additional_tools",
		"role":  "developer",
		"tools": newTools,
	})
	return items, nil
}

func mergeOpenAIResponsesLiteAdditionalTools(existing []any, moved []any) ([]any, error) {
	merged := append([]any(nil), existing...)
	seen := make(map[string]any, len(existing)+len(moved))
	for _, rawTool := range existing {
		if identity := openAIResponsesLiteToolIdentity(rawTool); identity != "" {
			if previous, exists := seen[identity]; exists && !reflect.DeepEqual(previous, rawTool) {
				return nil, fmt.Errorf("responses Lite additional_tools contains conflicting definitions for %s", openAIResponsesLiteToolIdentityForError(rawTool))
			}
			seen[identity] = rawTool
		}
	}
	for _, rawTool := range moved {
		identity := openAIResponsesLiteToolIdentity(rawTool)
		if identity != "" {
			if previous, exists := seen[identity]; exists {
				if reflect.DeepEqual(previous, rawTool) {
					continue
				}
				return nil, fmt.Errorf("responses Lite additional_tools conflicts with migrated %s", openAIResponsesLiteToolIdentityForError(rawTool))
			}
			seen[identity] = rawTool
		}
		merged = append(merged, rawTool)
	}
	return merged, nil
}

func openAIResponsesLiteToolIdentity(rawTool any) string {
	tool, ok := rawTool.(map[string]any)
	if !ok {
		return ""
	}
	toolType := strings.TrimSpace(firstNonEmptyString(tool["type"]))
	name := strings.TrimSpace(firstNonEmptyString(tool["name"]))
	if toolType == "" || name == "" {
		return ""
	}
	return toolType + "\x00" + name
}

func openAIResponsesLiteToolIdentityForError(rawTool any) string {
	tool, _ := rawTool.(map[string]any)
	return fmt.Sprintf("tool type %q name %q", strings.TrimSpace(firstNonEmptyString(tool["type"])), strings.TrimSpace(firstNonEmptyString(tool["name"])))
}

func normalizeOpenAIResponsesLiteToolsPayload(body []byte) ([]byte, bool, error) {
	requestBody, err := decodeOfficialJSONObjectUseNumber(body)
	if err != nil {
		return body, false, fmt.Errorf("decode responses Lite request body: %w", err)
	}
	changed, err := normalizeOpenAIResponsesLiteTools(requestBody)
	if err != nil || !changed {
		return body, false, err
	}
	rebuilt, err := marshalOfficialJSONObjectPreservingOrderAndRaw(requestBody, body)
	if err != nil {
		return body, false, fmt.Errorf("encode responses Lite request body: %w", err)
	}
	return rebuilt, true, nil
}
