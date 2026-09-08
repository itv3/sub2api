package service

import (
	"bytes"
	"encoding/json"
	"errors"
)

// 本文件把 UseNumber 语义的 JSON 解码改为“索引直建对象树”（docs/bug.md 6.4 第 3 点）。
//
// Go 1.27 的 encoding/json Decoder 从 64 字节起倍增内部读取缓冲，解码一个 17 MB 正文要
// 额外分配约 4 倍正文的缓冲；官方出站链上一个请求至少解码三次，这部分曾是放大倍数的
// 大头。索引扫描器一次只读扫描就能拿到全部值区间与结构，在其上直接构建
// map[string]any / []any / string / json.Number / bool / nil 的对象树，与
// Decoder.UseNumber().Decode 的结果逐字段一致：同名键取最后一次、数字保留十进制文本、
// 字符串按 encoding/json 规则反转义并把非法 UTF-8 逐字节替换为 U+FFFD、空容器为非 nil。
// 扫描失败或顶层不是对象时退回 encoding/json 路径，保证错误值与过去完全一致；扫描器
// 的语法只会比 encoding/json 更严，不会更宽（差分测试锁定）。

// buildOfficialJSONRawIndexForDecode 只登记节点、不计算结构摘要，也不建立复合值索引。
func buildOfficialJSONRawIndexForDecode(body []byte) (*officialJSONRawIndex, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("JSON 正文为空")
	}
	index := &officialJSONRawIndex{
		body:       body,
		nodes:      make([]officialJSONRawNode, 0, 64),
		skipDigest: true,
	}
	scanner := officialJSONRawScanner{index: index}
	root, err := scanner.parseValue(0)
	if err != nil {
		return nil, err
	}
	scanner.skipSpace()
	if scanner.pos != len(body) {
		return nil, errors.New("JSON 正文包含多个顶层值")
	}
	index.root = root
	return index, nil
}

// decodeValue 把索引节点还原为 encoding/json 解码到 any 时的 Go 值。
func (index *officialJSONRawIndex) decodeValue(node int32) any {
	n := &index.nodes[node]
	switch n.kind {
	case officialJSONRawKindObject:
		object := make(map[string]any, len(n.members))
		for _, member := range n.members {
			// 成员按原始顺序写入：同名键自然取最后一次出现，与 encoding/json 一致。
			object[member.key] = index.decodeValue(member.node)
		}
		return object
	case officialJSONRawKindArray:
		items := make([]any, len(n.items))
		for i, item := range n.items {
			items[i] = index.decodeValue(item)
		}
		return items
	case officialJSONRawKindString:
		return index.decodeString(node)
	case officialJSONRawKindNumber:
		return json.Number(index.body[n.start:n.end])
	case officialJSONRawKindTrue:
		return true
	case officialJSONRawKindFalse:
		return false
	default:
		return nil
	}
}

// decodeString 返回字符串节点反转义后的 Go 字符串；无转义且为合法 UTF-8 时直接复制原文。
func (index *officialJSONRawIndex) decodeString(node int32) string {
	n := &index.nodes[node]
	segment := index.body[n.start+1 : n.end-1]
	if !n.slowPath {
		return string(segment)
	}
	// 扫描阶段已经反转义校验过同一段字节，这里不会再出错。
	unescaped, err := officialJSONUnescape(index.scratch[:0], segment)
	index.scratch = unescaped[:0]
	if err != nil {
		return string(segment)
	}
	return string(unescaped)
}

// decodeOfficialJSONObjectUseNumber 在任何可能重新编码正文的官方出站路径中
// 保留 JSON 数字的十进制文本，防止大整数经过 float64 后发生不可逆改写。
func decodeOfficialJSONObjectUseNumber(body []byte) (map[string]any, error) {
	index, err := buildOfficialJSONRawIndexForDecode(body)
	if err != nil || index.nodes[index.root].kind != officialJSONRawKindObject {
		return decodeOfficialJSONObjectUseNumberSlow(body)
	}
	return index.decodeObject(index.root), nil
}

// decodeObject 把已确认为对象的节点还原为 map；调用方必须先检查节点类型。
func (index *officialJSONRawIndex) decodeObject(node int32) map[string]any {
	object, ok := index.decodeValue(node).(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return object
}

// decodeOfficialJSONValueUseNumber 以 UseNumber 语义解码任意 JSON 值。
func decodeOfficialJSONValueUseNumber(body []byte) (any, error) {
	index, err := buildOfficialJSONRawIndexForDecode(body)
	if err != nil {
		return decodeOfficialJSONValueUseNumberSlow(body)
	}
	return index.decodeValue(index.root), nil
}
