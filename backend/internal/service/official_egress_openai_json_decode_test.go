package service

import (
	"math/rand"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// 本文件锁定“索引直建对象树”解码器与 encoding/json UseNumber 路径的逐字段一致性。

var officialJSONDecodeFixtures = []string{
	`{}`,
	` { } `,
	`{"a":1}`,
	`{"a":1,"a":2}`,
	`{"a":{"b":[1,2,{"c":null}]},"a":{"b":"shadow"},"d":[]}`,
	`{"n":[0,-0,1,-1,1.5,-1.5,1e5,1E-5,1.25e+3,123456789012345678901234567890,0.1,1e400]}`,
	`{"s":"plain","e":"a\"b\\c\/d\b\f\n\r\t","u":"é中😀","lone":"\ud800x","lone2":"\udc00","end":"\ud83d"}`,
	`{"key":"escaped key","k\"q":1,"中文":2}`,
	"{\"bad\":\"\xff\xfe\",\"\xff\":\"key\",\"ok\":\"\xe4\xb8\xad\"}",
	`{"deep":[[[[[[[[[[{"x":[{}]}]]]]]]]]]]}`,
	`{"t":true,"f":false,"z":null,"empty":{},"emptyArr":[],"nested":{"empty":{},"arr":[[],{}]}}`,
	"{\n\t\"a\" : [ 1 , 2 , 3 ] ,\r\n \"b\" : { \"c\" : \"d\" } \n}\n",
	`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},{"type":"function_call","call_id":"call_1","name":"x","arguments":"{\"a\":1}"}]}`,
	`{"instructions":"` + strings.Repeat("x", 100000) + `"}`,
	`{"a":" "}`,
	`{"model":"gpt-5.6-codex","stream":true,"store":false,"include":["reasoning.encrypted_content"],"prompt_cache_key":" key "}`,
}

var officialJSONDecodeInvalidFixtures = []string{
	``, ` `, `{`, `}`, `{"a":1`, `{"a":1,}`, `{,}`, `{"a"}`, `{"a":}`, `{a:1}`, `{'a':1}`, `{"a":1}x`, `{"a":1} {"b":2}`,
	`{"a":1}{"b":2}`, `{"a":01}`, `{"a":1.}`, `{"a":.5}`, `{"a":+1}`, `{"a":-}`, `{"a":1e}`, `{"a":1e+}`, `{"a":NaN}`, `{"a":Infinity}`,
	`{"a":tru}`, `{"a":nul}`, `{"a":"\x"}`, `{"a":"\'"}`, `{"a":"\u12"}`, `{"a":"\u12g4"}`, "{\"a\":\"tab\there\"}", "{\"a\":\"nl\nhere\"}",
	`{"a":[1,]}`, `{"a":[,1]}`, `{"a":[1 2]}`, `{"a":{"b":1 "c":2}}`, "\ufeff{}", `null`, `[1]`, `"s"`, `1`, `true`,
	`{"a":"unterminated}`, `{"a":1}}`, `{"a":1]`, `{"a":"\ud800\u"}`, `{"a" 1}`, `{"a"::1}`, `{"a":1,,"b":2}`,
	"{\"a\":1}\x00", "{\"a\":\x001}",
}

func decodeCompareObject(t *testing.T, name string, body []byte) {
	t.Helper()
	fast, fastErr := decodeOfficialJSONObjectUseNumber(body)
	slow, slowErr := decodeOfficialJSONObjectUseNumberSlow(body)
	if (fastErr == nil) != (slowErr == nil) {
		t.Fatalf("%s：错误有无不一致 fast=%v slow=%v", name, fastErr, slowErr)
	}
	if slowErr != nil {
		require.Equal(t, slowErr.Error(), fastErr.Error(), "%s：错误文本不一致", name)
		return
	}
	if !reflect.DeepEqual(fast, slow) {
		t.Fatalf("%s：解码树不一致\nfast=%#v\nslow=%#v", name, fast, slow)
	}
}

func decodeCompareValue(t *testing.T, name string, body []byte) {
	t.Helper()
	fast, fastErr := decodeOfficialJSONValueUseNumber(body)
	slow, slowErr := decodeOfficialJSONValueUseNumberSlow(body)
	if (fastErr == nil) != (slowErr == nil) {
		t.Fatalf("%s：错误有无不一致 fast=%v slow=%v", name, fastErr, slowErr)
	}
	if slowErr != nil {
		require.Equal(t, slowErr.Error(), fastErr.Error(), "%s：错误文本不一致", name)
		return
	}
	if !reflect.DeepEqual(fast, slow) {
		t.Fatalf("%s：解码值不一致\nfast=%#v\nslow=%#v", name, fast, slow)
	}
}

func TestOfficialJSONIndexDecodeMatchesEncodingJSONOnFixtures(t *testing.T) {
	for i, fixture := range officialJSONDecodeFixtures {
		decodeCompareObject(t, "valid#"+strconv.Itoa(i), []byte(fixture))
		decodeCompareValue(t, "valid-value#"+strconv.Itoa(i), []byte(fixture))
		// 空容器必须与 encoding/json 一样是非 nil 值
		fast, err := decodeOfficialJSONObjectUseNumber([]byte(fixture))
		require.NoError(t, err)
		require.NotNil(t, fast)
	}
	for i, fixture := range officialJSONDecodeInvalidFixtures {
		decodeCompareObject(t, "invalid#"+strconv.Itoa(i), []byte(fixture))
		decodeCompareValue(t, "invalid-value#"+strconv.Itoa(i), []byte(fixture))
	}
	// 非对象顶层值：任意值解码必须成功，对象解码必须与旧路径同样的错误
	for _, fixture := range []string{`[1,{"a":"b"},[]]`, `"text"`, `12.5`, `true`, `null`, ` [] `} {
		decodeCompareValue(t, "scalar "+fixture, []byte(fixture))
		decodeCompareObject(t, "scalar-object "+fixture, []byte(fixture))
	}
	// 深度：10000 层在两条路径都必须成功，10001 层都必须失败
	for _, depth := range []int{9999, 10000, 10001, 10002} {
		body := []byte(`{"a":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `}`)
		decodeCompareObject(t, "depth "+strconv.Itoa(depth), body)
	}
}

// decodeRandomJSON 直接生成随机 JSON 文本（含随机空白、转义、重复键、非法 UTF-8）。
func decodeRandomJSON(rng *rand.Rand, depth int) string {
	space := func() string {
		return []string{"", " ", "\n", "\t ", "\r\n"}[rng.Intn(5)]
	}
	str := func() string {
		var b strings.Builder
		_ = b.WriteByte('"')
		for n := rng.Intn(6); n > 0; n-- {
			switch rng.Intn(9) {
			case 0:
				_, _ = b.WriteString(`\"`)
			case 1:
				_, _ = b.WriteString(`\\`)
			case 2:
				_, _ = b.WriteString(`\n`)
			case 3:
				_, _ = b.WriteString(`é`)
			case 4:
				_, _ = b.WriteString(`😀`)
			case 5:
				_, _ = b.WriteString(`\ud800`)
			case 6:
				_, _ = b.WriteString("\xff")
			case 7:
				_, _ = b.WriteString("中")
			default:
				_ = b.WriteByte(byte('a' + rng.Intn(26)))
			}
		}
		_ = b.WriteByte('"')
		return b.String()
	}
	if depth > 4 {
		return []string{"1", `"leaf"`, "null", "true", "-0.5e3"}[rng.Intn(5)]
	}
	switch rng.Intn(8) {
	case 0:
		return "null"
	case 1:
		return "true"
	case 2:
		return "false"
	case 3:
		return []string{"0", "-0", "12", "-7.25", "1e3", "1E+2", "0.001", "123456789012345678901234567890"}[rng.Intn(8)]
	case 4:
		return str()
	case 5:
		var b strings.Builder
		_, _ = b.WriteString("[")
		n := rng.Intn(4)
		for i := 0; i < n; i++ {
			if i > 0 {
				_, _ = b.WriteString(",")
			}
			_, _ = b.WriteString(space() + decodeRandomJSON(rng, depth+1) + space())
		}
		_, _ = b.WriteString("]")
		return b.String()
	default:
		var b strings.Builder
		_, _ = b.WriteString("{")
		n := rng.Intn(4)
		keys := []string{`"a"`, `"b"`, `"key"`, `"key"`, `"中"`, "\"\xff\"", `""`}
		for i := 0; i < n; i++ {
			if i > 0 {
				_, _ = b.WriteString(",")
			}
			_, _ = b.WriteString(space() + keys[rng.Intn(len(keys))] + space() + ":" + space() + decodeRandomJSON(rng, depth+1) + space())
		}
		_, _ = b.WriteString("}")
		return b.String()
	}
}

func decodeMutate(rng *rand.Rand, body []byte) []byte {
	out := append([]byte(nil), body...)
	alphabet := []byte("{}[]\",:\\ 0123456789abtfnu-+.eE\n\x00\xff'")
	for n := 1 + rng.Intn(3); n > 0; n-- {
		if len(out) == 0 {
			return out
		}
		pos := rng.Intn(len(out))
		switch rng.Intn(3) {
		case 0:
			out = append(out[:pos], out[pos+1:]...)
		case 1:
			out = append(out[:pos], append([]byte{alphabet[rng.Intn(len(alphabet))]}, out[pos:]...)...)
		default:
			out[pos] = alphabet[rng.Intn(len(alphabet))]
		}
	}
	return out
}

func TestOfficialJSONIndexDecodeMatchesEncodingJSONOnRandomDocuments(t *testing.T) {
	rng := rand.New(rand.NewSource(20260908))
	for round := 0; round < 3000; round++ {
		body := []byte(decodeRandomJSON(rng, 0))
		decodeCompareValue(t, "random#"+strconv.Itoa(round), body)
		decodeCompareObject(t, "random-object#"+strconv.Itoa(round), body)
		mutated := decodeMutate(rng, body)
		decodeCompareValue(t, "mutated#"+strconv.Itoa(round), mutated)
		decodeCompareObject(t, "mutated-object#"+strconv.Itoa(round), mutated)
	}
}

func TestOfficialJSONIndexDecodeDoesNotAmplifyLargeBody(t *testing.T) {
	body := testBuildLargeOfficialOpenAIBody(t, 32, 128*1024)
	measure := func(run func()) float64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		run()
		runtime.ReadMemStats(&after)
		return float64(after.TotalAlloc - before.TotalAlloc)
	}
	fast := measure(func() {
		_, err := decodeOfficialJSONObjectUseNumber(body)
		require.NoError(t, err)
	})
	slow := measure(func() {
		_, err := decodeOfficialJSONObjectUseNumberSlow(body)
		require.NoError(t, err)
	})
	t.Logf("正文 %.1f MiB：索引解码 %.1f MiB，encoding/json 解码 %.1f MiB", float64(len(body))/1024/1024, fast/1024/1024, slow/1024/1024)
	require.Less(t, fast, 2.0*float64(len(body)), "索引解码的分配必须低于 2 倍正文")
	require.Less(t, fast, slow/2, "索引解码必须比 encoding/json 路径省一半以上")
}
