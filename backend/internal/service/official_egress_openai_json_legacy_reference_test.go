package service

// 本文件是改造前「解码比对 + 全文查找池」编码器的逐字副本，只作为差分测试的参照实现，
// 证明字节区间拼接实现的输出与旧实现逐字节一致。生产代码不得引用这里的任何符号。

import (
	"bytes"
	"encoding/json"
	"sort"
)

type legacyOfficialJSONRawPool map[string]json.RawMessage

func legacyMarshalOfficialOrderedJSONObjectPreservingRaw(
	payload map[string]any,
	order []string,
	original []byte,
) ([]byte, error) {
	originalFields, originalKeys, _ := decodeOrderedRawJSONObject(original)
	originalPool := legacyCollectOfficialJSONCompositeRawValues(original)
	known := make(map[string]struct{}, len(order))
	keys := make([]string, 0, len(payload))
	for _, key := range order {
		known[key] = struct{}{}
		if _, exists := payload[key]; exists {
			keys = append(keys, key)
		}
	}
	unknownSeen := make(map[string]struct{}, len(payload)-len(keys))
	for _, key := range originalKeys {
		if _, exists := known[key]; exists {
			continue
		}
		if _, exists := payload[key]; !exists {
			continue
		}
		keys = append(keys, key)
		unknownSeen[key] = struct{}{}
	}
	unknown := make([]string, 0, len(payload)-len(keys))
	for key := range payload {
		if _, exists := known[key]; !exists {
			if _, exists := unknownSeen[key]; exists {
				continue
			}
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	keys = append(keys, unknown...)

	out := []byte{'{'}
	for index, key := range keys {
		if index > 0 {
			out = append(out, ',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		encodedValue, err := legacyMarshalOfficialJSONValuePreservingRaw(
			payload[key],
			originalFields[key],
			originalPool,
		)
		if err != nil {
			return nil, err
		}
		out = append(out, encodedKey...)
		out = append(out, ':')
		out = append(out, encodedValue...)
	}
	out = append(out, '}')
	return out, nil
}

func legacyMarshalOfficialJSONValuePreservingRaw(
	value any,
	original json.RawMessage,
	originalPool legacyOfficialJSONRawPool,
) ([]byte, error) {
	if len(original) > 0 {
		decoded, err := decodeOfficialJSONValueUseNumber(original)
		if err == nil && reflectOfficialJSONEqual(value, decoded) {
			return append([]byte(nil), original...), nil
		}
	}
	if pooled := legacyMatchOfficialJSONCompositeRawValue(value, originalPool); len(pooled) > 0 {
		return append([]byte(nil), pooled...), nil
	}

	switch typed := value.(type) {
	case map[string]any:
		return legacyMarshalOfficialNestedJSONObjectPreservingRaw(typed, original, originalPool)
	case []any:
		return legacyMarshalOfficialJSONArrayPreservingRaw(typed, original, originalPool)
	case json.RawMessage:
		if json.Valid(typed) {
			return append([]byte(nil), typed...), nil
		}
	}
	return marshalOpenAIUpstreamJSON(value)
}

func legacyMarshalOfficialNestedJSONObjectPreservingRaw(
	payload map[string]any,
	original json.RawMessage,
	originalPool legacyOfficialJSONRawPool,
) ([]byte, error) {
	originalFields, originalKeys, _ := decodeOrderedRawJSONObject(original)
	keys := make([]string, 0, len(payload))
	seen := make(map[string]struct{}, len(payload))
	for _, key := range originalKeys {
		if _, exists := payload[key]; !exists {
			continue
		}
		keys = append(keys, key)
		seen[key] = struct{}{}
	}
	additional := make([]string, 0, len(payload)-len(keys))
	for key := range payload {
		if _, exists := seen[key]; !exists {
			additional = append(additional, key)
		}
	}
	sort.Strings(additional)
	keys = append(keys, additional...)

	out := []byte{'{'}
	for index, key := range keys {
		if index > 0 {
			out = append(out, ',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		encodedValue, err := legacyMarshalOfficialJSONValuePreservingRaw(
			payload[key],
			originalFields[key],
			originalPool,
		)
		if err != nil {
			return nil, err
		}
		out = append(out, encodedKey...)
		out = append(out, ':')
		out = append(out, encodedValue...)
	}
	out = append(out, '}')
	return out, nil
}

func legacyMarshalOfficialJSONArrayPreservingRaw(
	items []any,
	original json.RawMessage,
	originalPool legacyOfficialJSONRawPool,
) ([]byte, error) {
	var originalItems []json.RawMessage
	_ = json.Unmarshal(original, &originalItems)
	used := make([]bool, len(originalItems))
	out := []byte{'['}
	for index, item := range items {
		if index > 0 {
			out = append(out, ',')
		}
		originalIndex := legacyMatchOfficialJSONOriginalArrayItem(item, originalItems, used)
		if originalIndex < 0 && index < len(originalItems) && !used[index] {
			originalIndex = index
		}
		var originalItem json.RawMessage
		if originalIndex >= 0 {
			used[originalIndex] = true
			originalItem = originalItems[originalIndex]
		}
		encoded, err := legacyMarshalOfficialJSONValuePreservingRaw(item, originalItem, originalPool)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	out = append(out, ']')
	return out, nil
}

// legacyCollectOfficialJSONCompositeRawValues 收集原始正文中的对象和数组字节。
// Profile 可能把工具或消息搬到另一个顶层字段；局部父节点因此无法直接命中，
// 全文池仍可复用未变化的用户对象，避免跨字段搬运时重排其内部键。
func legacyCollectOfficialJSONCompositeRawValues(body []byte) legacyOfficialJSONRawPool {
	values := make(legacyOfficialJSONRawPool, 32)
	var collect func(json.RawMessage)
	collect = func(raw json.RawMessage) {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
			return
		}
		decoded, err := decodeOfficialJSONValueUseNumber(trimmed)
		if err != nil {
			return
		}
		canonical, err := marshalOpenAIUpstreamJSON(decoded)
		if err != nil {
			return
		}
		key := string(canonical)
		if _, exists := values[key]; !exists {
			values[key] = append(json.RawMessage(nil), trimmed...)
		}
		if trimmed[0] == '{' {
			fields, keys, err := decodeOrderedRawJSONObject(trimmed)
			if err != nil {
				return
			}
			for _, key := range keys {
				collect(fields[key])
			}
			return
		}
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return
		}
		for _, item := range items {
			collect(item)
		}
	}
	collect(body)
	return values
}

func legacyMatchOfficialJSONCompositeRawValue(
	value any,
	originalPool legacyOfficialJSONRawPool,
) json.RawMessage {
	switch value.(type) {
	case map[string]any, []any:
	default:
		return nil
	}
	canonical, err := marshalOpenAIUpstreamJSON(value)
	if err != nil {
		return nil
	}
	return originalPool[string(canonical)]
}

func legacyMatchOfficialJSONOriginalArrayItem(
	item any,
	originalItems []json.RawMessage,
	used []bool,
) int {
	for index, raw := range originalItems {
		if used[index] {
			continue
		}
		decoded, err := decodeOfficialJSONValueUseNumber(raw)
		if err == nil && reflectOfficialJSONEqual(item, decoded) {
			return index
		}
	}
	return -1
}
