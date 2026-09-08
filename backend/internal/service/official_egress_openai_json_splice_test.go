package service

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// 本文件锁定 docs/bug.md 6.4 第 3 点与指南 §3.3「URL、header 与 body」小节：字节区间拼接编码器的输出必须与
// 改造前的「解码比对 + 全文查找池」实现逐字节一致，同时不再按正文体积成倍分配内存。

// spliceDifferential 用同一份 payload 与 original 分别跑新旧编码器，要求结果逐字节相等。
func spliceDifferential(t *testing.T, name string, payload map[string]any, order []string, original []byte) []byte {
	t.Helper()
	legacy, legacyErr := legacyMarshalOfficialOrderedJSONObjectPreservingRaw(payload, order, original)
	current, currentErr := marshalOfficialOrderedJSONObjectPreservingRaw(payload, order, original)
	if legacyErr != nil || currentErr != nil {
		require.Error(t, legacyErr, "%s：新实现报错但旧实现没有：%v", name, currentErr)
		require.Error(t, currentErr, "%s：旧实现报错但新实现没有：%v", name, legacyErr)
		return nil
	}
	require.Equal(t, string(legacy), string(current), "%s：拼接编码器输出必须与旧实现逐字节一致", name)
	require.True(t, json.Valid(current), "%s：输出必须是合法 JSON", name)
	return current
}

func spliceDecode(t *testing.T, original []byte) map[string]any {
	t.Helper()
	payload, err := decodeOfficialJSONObjectUseNumber(original)
	require.NoError(t, err)
	return payload
}

func spliceDeepCopy(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		copied := make(map[string]any, len(typed))
		for key, child := range typed {
			copied[key] = spliceDeepCopy(child)
		}
		return copied
	case []any:
		copied := make([]any, len(typed))
		for i, child := range typed {
			copied[i] = spliceDeepCopy(child)
		}
		return copied
	default:
		return value
	}
}

func TestSpliceEncoderMatchesLegacyOnHandWrittenFixtures(t *testing.T) {
	const big = "12345678901234567890"
	order := []string{"model", "instructions", "input", "tools", "tool_choice", "reasoning", "store", "stream"}
	fixtures := []struct {
		name     string
		original string
		mutate   func(map[string]any)
		order    []string
	}{
		{
			name:     "unchanged",
			original: `{"model":"gpt-5.4","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi\né \"q\""}]}],"payload":{"big":` + big + `,"z":1,"a":2}}`,
			mutate:   func(map[string]any) {},
			order:    order,
		},
		{
			name:     "top level scalar change keeps nested raw",
			original: `{ "model" : "gpt-5.4" ,"instructions":"old","input":[ {"type":"message","role":"user","content":"x"} ], "payload":{"big":` + big + `,"z":1,"a":2}}`,
			mutate:   func(p map[string]any) { p["instructions"] = "new" },
			order:    order,
		},
		{
			name:     "nested member change keeps sibling order",
			original: `{"model":"gpt-5.4","reasoning":{"effort":"low","summary":"auto","context":"none"},"input":"hi"}`,
			mutate: func(p map[string]any) {
				reasoning, _ := p["reasoning"].(map[string]any)
				reasoning["context"] = "all_turns"
			},
			order: order,
		},
		{
			name:     "new nested key appended sorted",
			original: `{"model":"gpt-5.4","reasoning":{"summary":"auto","effort":"low"}}`,
			mutate: func(p map[string]any) {
				reasoning, _ := p["reasoning"].(map[string]any)
				reasoning["a_new"] = "x"
				reasoning["zz"] = json.Number("3")
			},
			order: order,
		},
		{
			name:     "delete array item shifts positions",
			original: `{"input":[{"id":"1","text":"a "},{"id":"2","text":"b"},{"id":"3","text":"c"}]}`,
			mutate: func(p map[string]any) {
				input, _ := p["input"].([]any)
				p["input"] = []any{input[0], input[2]}
			},
		},
		{
			name:     "reorder and duplicate array items",
			original: `{"input":[{"id":"1"},{"id":"2"},{"id":"3","nested":{"z":1,"a":[1,2,{"q":null}]}}]}`,
			mutate: func(p map[string]any) {
				input, _ := p["input"].([]any)
				p["input"] = []any{input[2], input[0], input[1], input[0]}
			},
		},
		{
			name:     "insert fresh equal copy of an item",
			original: `{"input":[{"id":"1","c":{"z":1,"a":2}},{"id":"2"}]}`,
			mutate: func(p map[string]any) {
				input, _ := p["input"].([]any)
				p["input"] = append(input, spliceDeepCopy(input[0]))
			},
		},
		{
			name:     "per item key insertion (turn metadata)",
			original: `{"input":[{"type":"message","role":"user","content":"a"},{"type":"message","role":"assistant","content":"b"}],"client_metadata":{"session_id":"s"}}`,
			mutate: func(p map[string]any) {
				items, _ := p["input"].([]any)
				for _, item := range items {
					itemObject, _ := item.(map[string]any)
					itemObject["internal_chat_message_metadata_passthrough"] = map[string]any{"turn_id": "t"}
				}
			},
		},
		{
			name:     "move composite to another top level field",
			original: `{"tools":[{"type":"namespace","name":"ns","tools":[{"type":"function","name":"f","parameters":{"z":1,"a":2}}]}],"input":"hi"}`,
			mutate: func(p map[string]any) {
				tools, _ := p["tools"].([]any)
				ns, _ := tools[0].(map[string]any)
				p["tools"] = ns["tools"]
				nsTools, _ := ns["tools"].([]any)
				firstTool, _ := nsTools[0].(map[string]any)
				p["moved"] = firstTool["parameters"]
			},
			order: []string{"model", "input", "tools"},
		},
		{
			name:     "duplicate keys top level and nested",
			original: `{"model":"a","model":"b","obj":{"k":{"x":1},"k":{"x":2},"y":[{"d":1},{"d":1}]},"top_p":0.5,"top_p":0.6}`,
			mutate: func(p map[string]any) {
				p["extra"] = map[string]any{"x": json.Number("2")}
			},
		},
		{
			name:     "duplicate composite shadowed then referenced by fresh copy",
			original: `{"obj":{"k":{"x":1,"y":[1]},"k":{"x":2}},"other":"z"}`,
			mutate: func(p map[string]any) {
				p["fresh"] = map[string]any{"x": json.Number("1"), "y": []any{json.Number("1")}}
			},
		},
		{
			name:     "unicode surrogate pairs and escapes",
			original: `{"s":"😀 é \/ \b\f\n\r\t \u001f","t":"plain 中文 😀"}`,
			mutate:   func(p map[string]any) { p["u"] = "new \n 中" },
		},
		{
			name:     "lone surrogate coerced",
			original: `{"s":"\ud83d x","t":"\udc00"}`,
			mutate:   func(map[string]any) {},
		},
		{
			name:     "go numeric types against raw numbers",
			original: `{"a":100,"b":100.0,"c":1e2,"d":-0,"e":0.6}`,
			mutate: func(p map[string]any) {
				p["a"] = 100
				p["b"] = float64(100)
				p["c"] = int64(100)
				p["d"] = float64(0)
				p["e"] = 0.6
				p["f"] = json.Number("1.50")
			},
		},
		{
			name:     "raw message values",
			original: `{"a":{"z":1,"a":2},"b":[1,2]}`,
			mutate: func(p map[string]any) {
				p["a"] = json.RawMessage(`{"z":1,"a":2}`)
				p["b"] = json.RawMessage(`[1, 2]`)
				p["c"] = json.RawMessage(`{"bad":`)
			},
		},
		{
			name:     "exotic go types fall back",
			original: `{"a":["x","y"],"b":{"k":"v"}}`,
			mutate: func(p map[string]any) {
				p["a"] = []string{"x", "y"}
				p["b"] = map[string]string{"k": "v"}
				p["c"] = struct {
					Name string `json:"name"`
				}{Name: "n"}
			},
		},
		{
			name:     "type change object to array",
			original: `{"a":{"x":1},"b":[{"y":2}]}`,
			mutate: func(p map[string]any) {
				p["a"] = []any{map[string]any{"x": json.Number("1")}}
				p["b"] = map[string]any{"y": json.Number("2")}
			},
		},
		{
			name:     "pretty printed original",
			original: "{\n  \"model\": \"gpt-5.4\",\n  \"input\": [\n    {\n      \"type\": \"message\",\n      \"content\": \"a\"\n    }\n  ],\n  \"n\": [ 1 , 2 ]\n}\n",
			mutate:   func(p map[string]any) { p["model"] = "x" },
			order:    order,
		},
		{
			name:     "empty containers and nulls",
			original: `{"a":{},"b":[],"c":null,"d":"","e":[[],{}]}`,
			mutate:   func(p map[string]any) { p["f"] = nil },
		},
		{
			name:     "top level array original",
			original: `[{"x":1},{"y":2}]`,
			mutate:   func(map[string]any) {},
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			original := []byte(fixture.original)
			var payload map[string]any
			if decoded, err := decodeOfficialJSONObjectUseNumber(original); err == nil {
				payload = decoded
			} else {
				payload = map[string]any{"fresh": map[string]any{"x": json.Number("1")}}
			}
			fixture.mutate(payload)
			spliceDifferential(t, fixture.name, payload, fixture.order, original)
		})
	}
}

func TestSpliceEncoderMatchesLegacyWithoutOriginal(t *testing.T) {
	payload := map[string]any{
		"z": map[string]any{"b": json.Number("1"), "a": []any{"x", map[string]any{"k": nil}}},
		"a": "s",
		"m": 12,
	}
	spliceDifferential(t, "nil original", payload, []string{"m", "a"}, nil)
	spliceDifferential(t, "empty original", payload, nil, []byte("   "))
	spliceDifferential(t, "invalid original", payload, nil, []byte(`{"a":`))
	spliceDifferential(t, "trailing garbage", payload, nil, []byte(`{"a":1} x`))
}

// spliceRandomValue 生成随机 JSON 树，刻意覆盖转义、Unicode、控制字符、HTML 字符、
// 各种数字文本、空容器与嵌套。
func spliceRandomValue(rng *rand.Rand, depth int) any {
	if depth > 3 {
		return spliceRandomScalar(rng)
	}
	switch rng.Intn(6) {
	case 0:
		size := rng.Intn(5)
		object := make(map[string]any, size)
		for i := 0; i < size; i++ {
			object[spliceRandomKey(rng)] = spliceRandomValue(rng, depth+1)
		}
		return object
	case 1:
		size := rng.Intn(5)
		array := make([]any, 0, size)
		for i := 0; i < size; i++ {
			array = append(array, spliceRandomValue(rng, depth+1))
		}
		return array
	default:
		return spliceRandomScalar(rng)
	}
}

var spliceStringPool = []string{
	"", "plain", "with \"quote\"", "back\\slash", "new\nline", "tab\t", "ctrl\x01\x1f",
	"html <b>&</b>", "中文", "é", "😀", "  ", "mixed 中 😀 \n \"", "1", "true", "null",
	"long " + strings.Repeat("x", 40), "slash/", "\x00nul",
}

func spliceRandomScalar(rng *rand.Rand) any {
	switch rng.Intn(5) {
	case 0:
		return spliceStringPool[rng.Intn(len(spliceStringPool))]
	case 1:
		numbers := []string{"0", "-0", "1", "1.0", "1e2", "1E+2", "-1.5e-3", "12345678901234567890", "0.6", "100", "100.0"}
		return json.Number(numbers[rng.Intn(len(numbers))])
	case 2:
		return rng.Intn(2) == 0
	case 3:
		return nil
	default:
		return spliceStringPool[rng.Intn(len(spliceStringPool))]
	}
}

func spliceRandomKey(rng *rand.Rand) string {
	keys := []string{"a", "b", "c", "type", "role", "content", "text", "z", "key \"q\"", "中", "é", "html<", "id"}
	return keys[rng.Intn(len(keys))]
}

func spliceRandomObjects(value any, out *[]map[string]any) {
	switch typed := value.(type) {
	case map[string]any:
		*out = append(*out, typed)
		for _, child := range typed {
			spliceRandomObjects(child, out)
		}
	case []any:
		for _, child := range typed {
			spliceRandomObjects(child, out)
		}
	}
}

// spliceRandomMutate 对解码后的 payload 施加随机改写，覆盖顶层增删、嵌套改写、数组增删
// 重排、复合值搬运、等值新副本、Go 数值类型替换。
func spliceRandomMutate(rng *rand.Rand, payload map[string]any) {
	ops := rng.Intn(4)
	for i := 0; i < ops; i++ {
		switch rng.Intn(8) {
		case 0:
			payload[spliceRandomKey(rng)] = spliceRandomValue(rng, 1)
		case 1:
			for key := range payload {
				delete(payload, key)
				break
			}
		case 2:
			var objects []map[string]any
			spliceRandomObjects(payload, &objects)
			if len(objects) > 0 {
				target := objects[rng.Intn(len(objects))]
				target[spliceRandomKey(rng)] = spliceRandomScalar(rng)
			}
		case 3:
			for key, value := range payload {
				if array, ok := value.([]any); ok && len(array) > 0 {
					switch rng.Intn(3) {
					case 0:
						payload[key] = array[1:]
					case 1:
						swapped := append([]any(nil), array...)
						swapped[0], swapped[len(swapped)-1] = swapped[len(swapped)-1], swapped[0]
						payload[key] = swapped
					default:
						payload[key] = append(append([]any(nil), array...), spliceDeepCopy(array[0]))
					}
					break
				}
			}
		case 4:
			for key, value := range payload {
				switch value.(type) {
				case map[string]any, []any:
					payload["moved_"+key] = value
				}
				break
			}
		case 5:
			for key, value := range payload {
				payload[key] = spliceDeepCopy(value)
				break
			}
		case 6:
			for key, value := range payload {
				if _, ok := value.(json.Number); ok {
					switch rng.Intn(3) {
					case 0:
						payload[key] = 100
					case 1:
						payload[key] = float64(1)
					default:
						payload[key] = json.Number("1.0")
					}
					break
				}
			}
		default:
			payload["raw"] = json.RawMessage(`{"z":1,"a":2}`)
		}
	}
}

func TestSpliceEncoderMatchesLegacyOnRandomDocuments(t *testing.T) {
	rng := rand.New(rand.NewSource(20260908))
	for round := 0; round < 400; round++ {
		size := 1 + rng.Intn(6)
		document := make(map[string]any, size)
		for i := 0; i < size; i++ {
			document[spliceRandomKey(rng)] = spliceRandomValue(rng, 1)
		}
		original, err := json.Marshal(document)
		require.NoError(t, err)
		if rng.Intn(3) == 0 {
			var pretty bytes.Buffer
			require.NoError(t, json.Indent(&pretty, original, "", "  "))
			original = pretty.Bytes()
		}
		payload := spliceDecode(t, original)
		spliceRandomMutate(rng, payload)
		var order []string
		if rng.Intn(2) == 0 {
			order = []string{"type", "model", "a", "absent", "b"}
		}
		spliceDifferential(t, "random round "+strconv.Itoa(round), payload, order, original)
	}
}

func TestSpliceEncoderDoesNotAmplifyLargeBody(t *testing.T) {
	body := testBuildLargeOfficialOpenAIBody(t, 32, 128*1024)
	require.Greater(t, len(body), 8*1024*1024)
	payload := spliceDecode(t, body)
	payload["instructions"] = "changed"
	order := []string{"model", "instructions", "input", "tools"}

	var out []byte
	allocated := testMeasureAllocatedBytes(t, func() {
		var err error
		out, err = marshalOfficialOrderedJSONObjectPreservingRaw(payload, order, body)
		require.NoError(t, err)
	})
	require.Less(t, allocated, uint64(len(body))*3,
		"改一个顶层字段的编码累计分配 %d 字节，不得超过正文（%d 字节）的 3 倍；旧实现约为 70 倍", allocated, len(body))

	legacy, err := legacyMarshalOfficialOrderedJSONObjectPreservingRaw(payload, order, body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(legacy, out), "大正文输出必须与旧实现逐字节一致")

	// 改动一个 input 项：只有该项重编码，其余项仍拼接原始区间。
	items, _ := payload["input"].([]any)
	middle, _ := items[len(items)/2].(map[string]any)
	middle["role"] = "developer"
	allocated = testMeasureAllocatedBytes(t, func() {
		var err error
		out, err = marshalOfficialOrderedJSONObjectPreservingRaw(payload, order, body)
		require.NoError(t, err)
	})
	require.Less(t, allocated, uint64(len(body))*3,
		"改一个 input 项的编码累计分配 %d 字节，不得超过正文的 3 倍", allocated)
	require.Contains(t, string(out), `"role":"developer"`)
}

func TestOfficialJSONUnescapeMatchesEncodingJSON(t *testing.T) {
	cases := []string{
		`plain`, `a\"b`, `a\\b`, `a\/b`, `a\'b`, `\b\f\n\r\t`, `é`, `é`, `😀`,
		`\ud83d x`, `\udc00`, `\ud83dA`, `中文`, ` `, `a b`, "tab\there", "raw é 😀",
	}
	for _, raw := range cases {
		quoted := []byte(`"` + raw + `"`)
		var expected string
		expectedErr := json.Unmarshal(quoted, &expected)
		got, err := officialJSONUnescape(nil, []byte(raw))
		if expectedErr != nil {
			require.Error(t, err, "encoding/json 拒绝 %q 时实现也必须拒绝", raw)
			continue
		}
		require.NoError(t, err, "raw=%q", raw)
		require.Equal(t, expected, string(got), "raw=%q", raw)
	}
	invalid := []string{`\x`, `\u12`, `\uZZZZ`, `\`, "ctrl\x01"}
	for _, raw := range invalid {
		_, err := officialJSONUnescape(nil, []byte(raw))
		require.Error(t, err, "raw=%q", raw)
	}
	// 非法 UTF-8 逐字节替换为 U+FFFD，与 encoding/json 解码到 string 的结果一致。
	bad := []byte("a\xffb\xc3")
	var expected string
	require.NoError(t, json.Unmarshal(append(append([]byte(`"`), bad...), '"'), &expected))
	got, err := officialJSONUnescape(nil, bad)
	require.NoError(t, err)
	require.Equal(t, expected, string(got))
	require.True(t, utf8.Valid(got))
}

func TestOfficialJSONRawIndexRejectsInvalidDocuments(t *testing.T) {
	for _, invalid := range []string{``, `   `, `{`, `{"a":1} {}`, `{"a":01}`, `{"a":1.}`, `{"a":1e}`, `{"a":"x\q"}`, "{\"a\":\"x\x01\"}", `{"a":tru}`, `[1,]`, `{"a":1,}`, `{a:1}`, `{"a" 1}`} {
		_, err := buildOfficialJSONRawIndex([]byte(invalid))
		require.Error(t, err, "input=%q", invalid)
	}
	index, err := buildOfficialJSONRawIndex([]byte(" {\"a\" : [ 1 , {\"b\":\"c\"} ] , \"a\" : 2 } "))
	require.NoError(t, err)
	require.Equal(t, []string{"a"}, index.uniqueKeys(index.root), "重复键只登记首次出现")
	last := index.memberNode(index.root, "a")
	require.Equal(t, "2", string(index.raw(last)), "同名键取最后一次出现的值")
	require.Equal(t, `{"a" : [ 1 , {"b":"c"} ] , "a" : 2 }`, string(index.raw(index.root)), "区间去掉外围空白")
	require.Equal(t, -1, int(index.memberNode(index.root, "missing")))
}
