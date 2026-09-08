package officialegress

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// 本文件是 attempt Body 顶层字段定位的零分配扫描器（docs/bug.md 6.4 第 3 点）。
//
// encoding/json Decoder 会把整段 Body 复制进从 64 字节起倍增的内部缓冲，定位一次顶层
// 字段就要额外分配约 4 倍正文。这里只扫描不复制：字段名按 encoding/json 规则反转义，
// 值区间直接引用 source。扫描器的语法只会比 encoding/json 更严；任何语法疑点都以
// errJSONScanInvalid 交回 Decoder 路径复核，错误值与过去完全一致。

// jsonScanMaxDepth 与 encoding/json 的嵌套深度上限一致。
const jsonScanMaxDepth = 10000

// errJSONScanInvalid 表示扫描器无法确认语法合法，调用方应改走 Decoder 路径取得原始错误。
var errJSONScanInvalid = errors.New("JSON 扫描未通过")

func skipJSONSpace(src []byte, pos int) int {
	for pos < len(src) && isJSONSpace(src[pos]) {
		pos++
	}
	return pos
}

// skipJSONString 从 pos 处的引号开始定位字符串结束位置，返回闭合引号之后的位置与是否含转义。
func skipJSONString(src []byte, pos int) (end int, escaped bool, err error) {
	if pos >= len(src) || src[pos] != '"' {
		return 0, false, errJSONScanInvalid
	}
	i := pos + 1
	for {
		if i >= len(src) {
			return 0, false, errJSONScanInvalid
		}
		c := src[i]
		switch {
		case c == '"':
			return i + 1, escaped, nil
		case c == '\\':
			escaped = true
			i++
			if i >= len(src) {
				return 0, false, errJSONScanInvalid
			}
			switch src[i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				if i+4 >= len(src) {
					return 0, false, errJSONScanInvalid
				}
				for _, h := range src[i+1 : i+5] {
					if !isJSONHex(h) {
						return 0, false, errJSONScanInvalid
					}
				}
				i += 5
			default:
				return 0, false, errJSONScanInvalid
			}
		case c < 0x20:
			return 0, false, errJSONScanInvalid
		default:
			i++
		}
	}
}

func isJSONHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isJSONDigit(c byte) bool { return c >= '0' && c <= '9' }

func skipJSONNumber(src []byte, pos int) (int, error) {
	if pos < len(src) && src[pos] == '-' {
		pos++
	}
	if pos >= len(src) {
		return 0, errJSONScanInvalid
	}
	switch {
	case src[pos] == '0':
		pos++
	case src[pos] >= '1' && src[pos] <= '9':
		for pos < len(src) && isJSONDigit(src[pos]) {
			pos++
		}
	default:
		return 0, errJSONScanInvalid
	}
	if pos < len(src) && src[pos] == '.' {
		pos++
		digits := 0
		for pos < len(src) && isJSONDigit(src[pos]) {
			pos++
			digits++
		}
		if digits == 0 {
			return 0, errJSONScanInvalid
		}
	}
	if pos < len(src) && (src[pos] == 'e' || src[pos] == 'E') {
		pos++
		if pos < len(src) && (src[pos] == '+' || src[pos] == '-') {
			pos++
		}
		digits := 0
		for pos < len(src) && isJSONDigit(src[pos]) {
			pos++
			digits++
		}
		if digits == 0 {
			return 0, errJSONScanInvalid
		}
	}
	return pos, nil
}

func skipJSONLiteral(src []byte, pos int, literal string) (int, error) {
	if len(src)-pos < len(literal) || string(src[pos:pos+len(literal)]) != literal {
		return 0, errJSONScanInvalid
	}
	return pos + len(literal), nil
}

// skipJSONValue 从 pos（已跳过前导空白）开始校验并跳过一个 JSON 值，返回值结束位置。
// depth 是该值所在的总层数（顶层对象为 1），与 encoding/json 一样在超过 10000 层时拒绝。
func skipJSONValue(src []byte, pos int, depth int) (int, error) {
	if depth > jsonScanMaxDepth || pos >= len(src) {
		return 0, errJSONScanInvalid
	}
	switch src[pos] {
	case '{':
		return skipJSONObject(src, pos, depth)
	case '[':
		return skipJSONArray(src, pos, depth)
	case '"':
		end, _, err := skipJSONString(src, pos)
		return end, err
	case 't':
		return skipJSONLiteral(src, pos, "true")
	case 'f':
		return skipJSONLiteral(src, pos, "false")
	case 'n':
		return skipJSONLiteral(src, pos, "null")
	default:
		return skipJSONNumber(src, pos)
	}
}

func skipJSONObject(src []byte, pos int, depth int) (int, error) {
	pos = skipJSONSpace(src, pos+1)
	if pos < len(src) && src[pos] == '}' {
		return pos + 1, nil
	}
	for {
		end, _, err := skipJSONString(src, pos)
		if err != nil {
			return 0, err
		}
		pos = skipJSONSpace(src, end)
		if pos >= len(src) || src[pos] != ':' {
			return 0, errJSONScanInvalid
		}
		pos = skipJSONSpace(src, pos+1)
		if pos, err = skipJSONValue(src, pos, depth+1); err != nil {
			return 0, err
		}
		pos = skipJSONSpace(src, pos)
		if pos >= len(src) {
			return 0, errJSONScanInvalid
		}
		switch src[pos] {
		case ',':
			pos = skipJSONSpace(src, pos+1)
		case '}':
			return pos + 1, nil
		default:
			return 0, errJSONScanInvalid
		}
	}
}

func skipJSONArray(src []byte, pos int, depth int) (int, error) {
	pos = skipJSONSpace(src, pos+1)
	if pos < len(src) && src[pos] == ']' {
		return pos + 1, nil
	}
	for {
		var err error
		if pos, err = skipJSONValue(src, pos, depth+1); err != nil {
			return 0, err
		}
		pos = skipJSONSpace(src, pos)
		if pos >= len(src) {
			return 0, errJSONScanInvalid
		}
		switch src[pos] {
		case ',':
			pos = skipJSONSpace(src, pos+1)
		case ']':
			return pos + 1, nil
		default:
			return 0, errJSONScanInvalid
		}
	}
}

// decodeJSONFieldName 把带引号的字段名还原为 Go 字符串：无转义且为合法 UTF-8 时直接复制，
// 否则交给 encoding/json，保证非法 UTF-8 与代理对的处理与 Decoder.Token 完全一致。
func decodeJSONFieldName(quoted []byte, escaped bool) (string, error) {
	segment := quoted[1 : len(quoted)-1]
	if !escaped && utf8.Valid(segment) {
		return string(segment), nil
	}
	var name string
	if err := json.Unmarshal(quoted, &name); err != nil {
		return "", errJSONScanInvalid
	}
	return name, nil
}

// scanOrderedJSONFields 定位顶层对象的全部字段：字段名反转义、值区间引用 source、
// 顶层重复字段按与 Decoder 路径相同的顺序 fail-close。语法疑点返回 errJSONScanInvalid。
func scanOrderedJSONFields(source []byte) ([]orderedJSONField, map[string]int, error) {
	pos := skipJSONSpace(source, 0)
	if pos >= len(source) || source[pos] != '{' {
		return nil, nil, errJSONScanInvalid
	}
	fields := make([]orderedJSONField, 0, 16)
	fieldIndex := make(map[string]int)
	pos = skipJSONSpace(source, pos+1)
	if pos < len(source) && source[pos] == '}' {
		pos++
	} else {
		for {
			end, escaped, err := skipJSONString(source, pos)
			if err != nil {
				return nil, nil, err
			}
			name, err := decodeJSONFieldName(source[pos:end], escaped)
			if err != nil {
				return nil, nil, err
			}
			if _, duplicate := fieldIndex[name]; duplicate {
				return nil, nil, fmt.Errorf("JSON Body 字段重复: %s", name)
			}
			pos = skipJSONSpace(source, end)
			if pos >= len(source) || source[pos] != ':' {
				return nil, nil, errJSONScanInvalid
			}
			valueStart := skipJSONSpace(source, pos+1)
			valueEnd, err := skipJSONValue(source, valueStart, 2)
			if err != nil {
				return nil, nil, err
			}
			fieldIndex[name] = len(fields)
			fields = append(fields, orderedJSONField{
				name: name, value: json.RawMessage(source[valueStart:valueEnd]),
			})
			pos = skipJSONSpace(source, valueEnd)
			if pos >= len(source) {
				return nil, nil, errJSONScanInvalid
			}
			if source[pos] == ',' {
				pos = skipJSONSpace(source, pos+1)
				continue
			}
			if source[pos] != '}' {
				return nil, nil, errJSONScanInvalid
			}
			pos++
			break
		}
	}
	if skipJSONSpace(source, pos) != len(source) {
		return nil, nil, errJSONScanInvalid
	}
	return fields, fieldIndex, nil
}
