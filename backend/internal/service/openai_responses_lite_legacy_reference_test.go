package service

import "fmt"

// legacyNormalizeOpenAIResponsesLiteToolsPayload 是加入零解码预检之前的实现：总是先把整段
// 正文解码成对象树再判断。差分测试用它锁定预检不改变任何输出与错误。
func legacyNormalizeOpenAIResponsesLiteToolsPayload(body []byte) ([]byte, bool, error) {
	requestBody, err := decodeOfficialJSONObjectUseNumberSlow(body)
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
