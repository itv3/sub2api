package service

import (
	"unsafe"

	"github.com/tidwall/gjson"
)

// 本文件提供请求正文的零拷贝只读视图（docs/bug.md 6.4 第 3 点）。
//
// gjson.GetBytes 会把命中的原始片段复制一份返回：对 input 这类占正文绝大部分的字段，
// 每次调用都等于再复制整段正文；12 MB 级的 Codex 轮次在转发链上被这样复制过五次以上。
// gjson.Get 对字符串视图只返回子串，因此这里先把 body 零拷贝地转成 string 再查询。
// 约束：返回的 Result 及其 Raw/Str 都指向 body 的内存，只能在 body 存活且不被修改的
// 期间使用，不得跨请求保存；需要长期持有时必须显式复制。

// openAIBodyString 返回正文的零拷贝字符串视图。
func openAIBodyString(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(body), len(body))
}

// openAIBodyGet 以零拷贝方式按 gjson 路径读取正文字段。
func openAIBodyGet(body []byte, path string) gjson.Result {
	if len(body) == 0 {
		return gjson.Result{}
	}
	return gjson.Get(openAIBodyString(body), path)
}

// openAIBodyRoot 返回正文顶层值的零拷贝视图，供 ForEach 一次遍历全部顶层成员。
func openAIBodyRoot(body []byte) gjson.Result {
	if len(body) == 0 {
		return gjson.Result{}
	}
	return gjson.Parse(openAIBodyString(body))
}

// openAIBodyHasAnyTopLevelKey 一次遍历判断顶层对象是否含有任一给定键。
func openAIBodyHasAnyTopLevelKey(body []byte, keys ...string) bool {
	root := openAIBodyRoot(body)
	if !root.IsObject() {
		return false
	}
	found := false
	root.ForEach(func(memberKey, _ gjson.Result) bool {
		for _, key := range keys {
			if memberKey.Str == key {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
