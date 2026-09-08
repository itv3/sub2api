package service

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// 本文件锁定“减少解码副本”变更集（docs/bug.md 6.4 第 3 点）的等价性：契约零拷贝捕获、
// 遗留入口与 compaction trigger 的只读预检、Finalizer 共享解码、zstd 编码器复用、
// 零拷贝正文读取，输出都必须与改造前的实现逐字节（或逐字段）一致。

func decodeSharingErrorParity(t *testing.T, name string, legacyErr, currentErr error) bool {
	t.Helper()
	if legacyErr != nil || currentErr != nil {
		require.Error(t, legacyErr, "%s：新实现报错但旧实现没有：%v", name, currentErr)
		require.Error(t, currentErr, "%s：旧实现报错但新实现没有：%v", name, legacyErr)
		return true
	}
	return false
}

func decodeSharingRandomBody(rng *rand.Rand) []byte {
	size := 1 + rng.Intn(6)
	document := make(map[string]any, size)
	for i := 0; i < size; i++ {
		document[spliceRandomKey(rng)] = spliceRandomValue(rng, 1)
	}
	if rng.Intn(2) == 0 {
		items := make([]any, 0, 6)
		for i := 0; i < rng.Intn(6); i++ {
			switch rng.Intn(6) {
			case 0:
				items = append(items, map[string]any{"type": "additional_tools", "role": "developer", "tools": []any{map[string]any{"type": "custom", "name": "x", "n": json.Number("9007199254740993")}}})
			case 1:
				items = append(items, map[string]any{"type": "function_call", "call_id": " id" + strconv.Itoa(i) + " ", "name": "f"})
			case 2:
				items = append(items, map[string]any{"type": "custom_tool_call_output", "call_id": "", "output": "o"})
			case 3:
				items = append(items, map[string]any{"type": "compaction_trigger"})
			case 4:
				items = append(items, spliceRandomValue(rng, 2))
			default:
				items = append(items, map[string]any{"type": "message", "role": "user", "content": spliceStringPool[rng.Intn(len(spliceStringPool))]})
			}
		}
		document["input"] = items
	}
	for _, key := range []string{"instructions", "include", "parallel_tool_calls", "prompt_cache_key", "client_metadata", "messages", "prompt", "commands"} {
		if rng.Intn(4) == 0 {
			document[key] = spliceRandomValue(rng, 2)
		}
	}
	body, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	if rng.Intn(3) == 0 {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, body, "", " "); err == nil {
			body = pretty.Bytes()
		}
	}
	return body
}

func TestCaptureOfficialOpenAIHTTPBodyContractMatchesLegacy(t *testing.T) {
	fixtures := map[string][]byte{
		"official_explicit_tool":  newOfficialOpenAIHTTPTestBody(t, false, true, true),
		"official_plain":          newOfficialOpenAIHTTPTestBody(t, true, false, false),
		"mixed_items":             []byte(`{"instructions":null,"include":["a",1],"parallel_tool_calls":true,"prompt_cache_key":"  k  ","client_metadata":{"z":9007199254740993,"a":"b"},"input":[{"type":"additional_tools","tools":[{"type":"custom","name":"x"}]},{"type":"function_call","call_id":" c1 "},{"type":"function_call_output","call_id":""},{"type":"custom_tool_call","call_id":"c2","type":"message"},5,"s",{"type":["x"],"call_id":"c3"},{"type":"tool_call","call_id":7},{"call_id":"orphan","type":"local_shell_call"}]}`),
		"duplicate_top_level":     []byte(`{"instructions":"a","instructions":{"x":1},"input":"s","input":[{"type":"local_shell_call","call_id":"q"}],"prompt_cache_key":5,"client_metadata":"nope","include":null,"include":["b"]}`),
		"escaped_keys":            []byte(`{"instructions":"e","input":[{"type":"function_call","call_id":"esc"}],"client_metadata":{"kéy":"v"}}`),
		"whitespace_prompt_key":   []byte(`{"prompt_cache_key":"   ","client_metadata":[1],"parallel_tool_calls":null}`),
		"unicode_call_id":         []byte(`{"input":[{"type":"mcp_tool_call","call_id":"中文 😀 \"q\" é"}]}`),
		"input_string":            []byte(`{"input":"hello","instructions":["a",{"b":1}]}`),
		"empty_object":            []byte(`{}`),
		"pretty":                  []byte("{\n  \"instructions\": \"x\",\n  \"input\": [\n    {\"type\": \"function_call\", \"call_id\": \"p\"}\n  ]\n}\n"),
		"invalid_truncated":       []byte(`{"a":`),
		"invalid_top_level_array": []byte(`[{"type":"function_call","call_id":"x"}]`),
		"invalid_trailing":        []byte(`{"a":1} x`),
		"invalid_empty":           []byte(``),
		"invalid_null":            []byte(`null`),
		"invalid_leading_zero":    []byte(`{"a":01}`),
		"invalid_escape":          []byte(`{"input":[{"type":"x\q"}]}`),
	}
	rng := rand.New(rand.NewSource(20260908))
	for round := 0; round < 300; round++ {
		fixtures["random_"+strconv.Itoa(round)] = decodeSharingRandomBody(rng)
	}
	for name, body := range fixtures {
		legacy, legacyErr := legacyCaptureOfficialOpenAIHTTPBodyContract(body)
		current, currentErr := captureOfficialOpenAIHTTPBodyContract(body)
		if decodeSharingErrorParity(t, name, legacyErr, currentErr) {
			continue
		}
		require.True(t, reflect.DeepEqual(legacy, current), "%s：契约捕获结果必须逐字段一致\n旧=%#v\n新=%#v", name, legacy, current)
	}
}

func TestCaptureOfficialOpenAIHTTPBodyContractDoesNotDecodeLargeBody(t *testing.T) {
	body := testBuildLargeOfficialOpenAIBody(t, 32, 128*1024)
	var contract *officialOpenAIHTTPBodyContract
	allocated := testMeasureAllocatedBytes(t, func() {
		var err error
		contract, err = captureOfficialOpenAIHTTPBodyContract(body)
		require.NoError(t, err)
	})
	require.NotNil(t, contract)
	require.Less(t, allocated, uint64(len(body))/8,
		"契约捕获分配 %d 字节，不得再按正文体积（%d 字节）成倍分配", allocated, len(body))
}

func TestNormalizeOpenAIResponsesLegacyIngressPrecheckMatchesLegacy(t *testing.T) {
	fixtures := map[string][]byte{
		"no_alias":            newOfficialOpenAIHTTPTestBody(t, false, false, true),
		"large_no_alias":      testBuildLargeOfficialOpenAIBody(t, 8, 64*1024),
		"messages":            []byte(`{"model":"gpt-5.4","messages":[{"role":"system","content":"s"},{"role":"user","content":"hi"}],"max_tokens":5}`),
		"messages_with_input": []byte(`{"messages":[{"role":"user","content":"hi"}],"input":"native","previous_response_id":"r"}`),
		"messages_empty":      []byte(`{"messages":[],"input":"x"}`),
		"messages_not_array":  []byte(`{"messages":"x"}`),
		"prompt_string":       []byte(`{"prompt":"p","model":"m"}`),
		"prompt_with_input":   []byte(`{"prompt":"p","input":"i"}`),
		"prompt_object":       []byte(`{"prompt":{"id":"tpl"},"input":"i"}`),
		"prompt_null":         []byte(`{"prompt":null,"input":null}`),
		"commands":            []byte(`{"commands":["a"],"input":"i"}`),
		"duplicate_messages":  []byte(`{"messages":[{"role":"user","content":"a"}],"messages":[]}`),
		"escaped_key":         []byte(`{"commands":[1],"input":"i"}`),
		"invalid_truncated":   []byte(`{"input":`),
		"invalid_trailing":    []byte(`{"input":"i"} {}`),
		"top_level_array":     []byte(`[1]`),
		"empty":               []byte(``),
	}
	rng := rand.New(rand.NewSource(20260909))
	for round := 0; round < 200; round++ {
		fixtures["random_"+strconv.Itoa(round)] = decodeSharingRandomBody(rng)
	}
	for name, body := range fixtures {
		legacy, legacyChanged, legacyErr := legacyNormalizeOpenAIResponsesLegacyIngress(body)
		current, currentChanged, currentErr := normalizeOpenAIResponsesLegacyIngress(body)
		if decodeSharingErrorParity(t, name, legacyErr, currentErr) {
			continue
		}
		require.Equal(t, legacyChanged, currentChanged, "%s：changed 标志必须一致", name)
		require.Equal(t, string(legacy), string(current), "%s：输出必须逐字节一致", name)
	}
}

func TestNormalizeCompactionTriggerInputOrderPrecheckMatchesLegacy(t *testing.T) {
	trigger := `{"type":"compaction_trigger"}`
	fixtures := map[string][]byte{
		"no_trigger":           newOfficialOpenAIHTTPTestBody(t, false, false, true),
		"large_no_trigger":     testBuildLargeOfficialOpenAIBody(t, 8, 64*1024),
		"trigger_last":         []byte(`{"input":[{"type":"message","content":"a"},` + trigger + `]}`),
		"trigger_middle":       []byte(`{"input":[` + trigger + `,{"type":"message","content":"a"}]}`),
		"two_triggers":         []byte(`{"input":[` + trigger + `,{"type":"message"},` + trigger + `]}`),
		"only_trigger":         []byte(`{"input":[` + trigger + `]}`),
		"trigger_dup_type":     []byte(`{"input":[{"type":"compaction_trigger","type":"message"},{"type":"message"}]}`),
		"trigger_type_escaped": []byte(`{"input":[{"type":"compaction_trigger"},{"type":"message"}]}`),
		"input_string":         []byte(`{"input":"x"}`),
		"input_empty":          []byte(`{"input":[]}`),
		"input_duplicate":      []byte(`{"input":[` + trigger + `,{"type":"m"}],"input":[{"type":"m"}]}`),
		"non_object_items":     []byte(`{"input":[1,"s",null,` + trigger + `,{"type":"m"}]}`),
		"invalid_truncated":    []byte(`{"input":[`),
		"invalid_trailing":     []byte(`{"input":[]} x`),
		"top_level_array":      []byte(`[` + trigger + `]`),
	}
	rng := rand.New(rand.NewSource(20260910))
	for round := 0; round < 200; round++ {
		fixtures["random_"+strconv.Itoa(round)] = decodeSharingRandomBody(rng)
	}
	for name, body := range fixtures {
		legacy, legacyChanged, legacyErr := legacyNormalizeCompactionTriggerInputOrder(body)
		current, currentChanged, currentErr := NormalizeCompactionTriggerInputOrder(body)
		if decodeSharingErrorParity(t, name, legacyErr, currentErr) {
			continue
		}
		require.Equal(t, legacyChanged, currentChanged, "%s：changed 标志必须一致", name)
		require.Equal(t, string(legacy), string(current), "%s：输出必须逐字节一致", name)
	}
}

func TestLegacyIngressAndCompactionPrechecksDoNotDecodeLargeBody(t *testing.T) {
	body := testBuildLargeOfficialOpenAIBody(t, 32, 128*1024)
	allocated := testMeasureAllocatedBytes(t, func() {
		_, changed, err := normalizeOpenAIResponsesLegacyIngress(body)
		require.NoError(t, err)
		require.False(t, changed)
	})
	require.Less(t, allocated, uint64(1<<20), "遗留入口预检分配 %d 字节，不得解码整段正文", allocated)
	allocated = testMeasureAllocatedBytes(t, func() {
		_, changed, err := NormalizeCompactionTriggerInputOrder(body)
		require.NoError(t, err)
		require.False(t, changed)
	})
	require.Less(t, allocated, uint64(1<<20), "compaction trigger 预检分配 %d 字节，不得解码整段正文", allocated)
}

func TestFinalizeOfficialOpenAIHTTPBodyPayloadMatchesBytesVariant(t *testing.T) {
	account := newOfficialOpenAIHTTPTestAccount(94990)
	for _, stream := range []bool{false, true} {
		for _, explicit := range []bool{false, true} {
			for _, tool := range []bool{false, true} {
				for _, lite := range []bool{false, true} {
					body := newOfficialOpenAIHTTPTestBody(t, stream, explicit, tool)
					contract, err := captureGeneratedOfficialOpenAIHTTPBodyContract(body)
					require.NoError(t, err)
					identity, err := deriveOfficialOpenAIHTTPIdentity(nil, account, body, contract, officialClientProfileModeActive)
					require.NoError(t, err)
					options := officialOpenAIHTTPBodyOptions{
						ProfileMode:           officialClientProfileModeActive,
						UseResponsesLite:      lite,
						SupportsParallelTools: true,
					}
					legacy, legacyModified, legacyErr := finalizeOfficialOpenAIHTTPBody(body, contract, identity, officialOpenAIReasoningDefaults{}, options)
					payload, err := decodeOfficialJSONObjectUseNumber(body)
					require.NoError(t, err)
					current, currentModified, currentErr := finalizeOfficialOpenAIHTTPBodyPayload(payload, body, contract, identity, officialOpenAIReasoningDefaults{}, options)
					name := "stream=" + strconv.FormatBool(stream) + " explicit=" + strconv.FormatBool(explicit) + " tool=" + strconv.FormatBool(tool) + " lite=" + strconv.FormatBool(lite)
					if decodeSharingErrorParity(t, name, legacyErr, currentErr) {
						continue
					}
					require.Equal(t, legacyModified, currentModified, name)
					require.Equal(t, string(legacy), string(current), "%s：已解码入口与字节入口必须逐字节一致", name)
				}
			}
		}
	}
	_, _, err := finalizeOfficialOpenAIHTTPBodyPayload(nil, nil, &officialOpenAIHTTPBodyContract{}, officialOpenAIHTTPIdentity{}, officialOpenAIReasoningDefaults{}, officialOpenAIHTTPBodyOptions{})
	require.Error(t, err)
}

func TestCompressOfficialOpenAIHTTPRequestMatchesFreshEncoder(t *testing.T) {
	rng := rand.New(rand.NewSource(20260911))
	random := make([]byte, 1<<20)
	_, _ = rng.Read(random)
	inputs := map[string][]byte{
		"small":      []byte(`{"model":"gpt-5.4","input":"hi"}`),
		"repetitive": bytes.Repeat([]byte(`{"type":"message","content":"同样的内容 same content "}`), 20000),
		"random":     random,
		"empty":      {},
	}
	for _, level := range []int{1, 3, 5, 9, 19} {
		for name, input := range inputs {
			legacyReq, err := http.NewRequest(http.MethodPost, "https://example.com/v1/responses", nil)
			require.NoError(t, err)
			currentReq, err := http.NewRequest(http.MethodPost, "https://example.com/v1/responses", nil)
			require.NoError(t, err)
			require.NoError(t, legacyCompressOfficialOpenAIHTTPRequest(legacyReq, input, level))
			require.NoError(t, compressOfficialOpenAIHTTPRequest(currentReq, input, level))
			legacyBody, err := legacyReq.GetBody()
			require.NoError(t, err)
			currentBody, err := currentReq.GetBody()
			require.NoError(t, err)
			legacyBytes, err := readAllForTest(legacyBody)
			require.NoError(t, err)
			currentBytes, err := readAllForTest(currentBody)
			require.NoError(t, err)
			require.Equal(t, legacyBytes, currentBytes, "level=%d input=%s：复用编码器输出必须逐字节一致", level, name)
			require.Equal(t, legacyReq.ContentLength, currentReq.ContentLength)
			require.Equal(t, "zstd", currentReq.Header.Get("Content-Encoding"))
		}
	}
	// 并发调用共享编码器必须各自得到独立且相同的输出。
	var wg sync.WaitGroup
	outputs := make([][]byte, 8)
	for i := range outputs {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, "https://example.com/v1/responses", nil)
			if err := compressOfficialOpenAIHTTPRequest(req, inputs["repetitive"], 3); err != nil {
				return
			}
			reader, _ := req.GetBody()
			outputs[slot], _ = readAllForTest(reader)
		}(i)
	}
	wg.Wait()
	for i := 1; i < len(outputs); i++ {
		require.Equal(t, outputs[0], outputs[i], "并发压缩输出必须一致")
	}
}

func TestOpenAIBodyGetMatchesGetBytes(t *testing.T) {
	bodies := [][]byte{
		newOfficialOpenAIHTTPTestBody(t, false, true, true),
		[]byte(`{"input":"s","messages":[{"role":"a"},{"role":"b"}],"tools":[{"type":"function"}],"n":9007199254740993,"e":"é\n"}`),
		[]byte(``),
		[]byte(`not json`),
	}
	rng := rand.New(rand.NewSource(20260912))
	for round := 0; round < 100; round++ {
		bodies = append(bodies, decodeSharingRandomBody(rng))
	}
	paths := []string{"input", "model", "messages.#-1", "tools.0.type", "missing", "n", "e", "input.0.type", "client_metadata.session_id"}
	for _, body := range bodies {
		for _, path := range paths {
			expected := gjson.GetBytes(body, path)
			actual := openAIBodyGet(body, path)
			require.Equal(t, expected.Type, actual.Type, "path=%s", path)
			require.Equal(t, expected.Raw, actual.Raw, "path=%s", path)
			require.Equal(t, expected.Str, actual.Str, "path=%s", path)
			require.Equal(t, expected.Num, actual.Num, "path=%s", path)
			require.Equal(t, expected.Exists(), actual.Exists(), "path=%s", path)
		}
		decoded, err := decodeOfficialJSONObjectUseNumber(body)
		if err == nil {
			index, indexErr := buildOfficialJSONRawIndexForDecode(body)
			require.NoError(t, indexErr)
			value, exists := decoded["input"]
			node := index.memberNode(index.root, "input")
			require.Equal(t, exists, node >= 0, "顶层 input 存在性必须与解码一致")
			if exists {
				canonical, err := marshalOpenAIUpstreamJSON(value)
				require.NoError(t, err)
				viaRaw, err := decodeOfficialJSONValueUseNumber(index.raw(node))
				require.NoError(t, err)
				canonicalRaw, err := marshalOpenAIUpstreamJSON(viaRaw)
				require.NoError(t, err)
				require.Equal(t, string(canonical), string(canonicalRaw), "同名键取最后一次必须与解码语义一致")
			}
		}
	}
	require.True(t, openAIBodyHasAnyTopLevelKey([]byte(`{"a":1,"messages":[]}`), "prompt", "messages"))
	require.False(t, openAIBodyHasAnyTopLevelKey([]byte(`{"a":{"messages":1}}`), "messages"))
	require.False(t, openAIBodyHasAnyTopLevelKey([]byte(`[{"messages":1}]`), "messages"))
}

func TestSanitizeOpenAIResponsesInputItemIDsMatchesLegacy(t *testing.T) {
	fixtures := map[string][]byte{
		"official":        newOfficialOpenAIHTTPTestBody(t, false, false, true),
		"large":           testBuildLargeOfficialOpenAIBody(t, 8, 64*1024),
		"message_ids":     []byte(`{"input":[{"type":"message","id":"msg_1","content":"a"},{"type":"message","id":"rs_x","content":"b"},{"type":"reasoning","id":"rs_2","summary":[]},{"type":"function_call","id":"fc_1","call_id":"c"},{"type":"message","id":7},"s",5,{"type":"function_call_output","call_id":"c2","output":"o"},{"type":"item_reference","id":"msg_ref"}]}`),
		"no_ids":          []byte(`{"input":[{"type":"message","content":"a"}]}`),
		"input_string":    []byte(`{"input":"x"}`),
		"escaped":         []byte(`{"input":[{"type":"message","id":"msg_1","content":"é"}]}`),
		"call_id_nonpair": []byte(`{"input":[{"type":"message","call_id":"x","content":"a"},{"type":"reasoning","call_id":"y"}]}`),
	}
	rng := rand.New(rand.NewSource(20260913))
	for round := 0; round < 200; round++ {
		fixtures["random_"+strconv.Itoa(round)] = decodeSharingRandomBody(rng)
	}
	for name, body := range fixtures {
		legacy, legacyChanged, legacyErr := legacySanitizeOpenAIResponsesInputItemIDs(body)
		current, currentChanged, currentErr := sanitizeOpenAIResponsesInputItemIDs(body)
		if decodeSharingErrorParity(t, name, legacyErr, currentErr) {
			continue
		}
		require.Equal(t, legacyChanged, currentChanged, name)
		require.Equal(t, string(legacy), string(current), "%s：输出必须逐字节一致", name)
	}
}

func readAllForTest(reader interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var out bytes.Buffer
	buffer := make([]byte, 64*1024)
	for {
		n, err := reader.Read(buffer)
		_, _ = out.Write(buffer[:n])
		if err != nil {
			if strings.Contains(err.Error(), "EOF") {
				return out.Bytes(), nil
			}
			return nil, err
		}
	}
}
