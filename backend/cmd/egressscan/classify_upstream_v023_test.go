package main

import "testing"

func TestSub2APIV023NewSinksHaveExplicitClassification(t *testing.T) {
	cases := []struct {
		name        string
		function    string
		file        string
		wantPersona string
		wantSink    string
	}{
		{
			name:        "chat completions internal implementation",
			function:    "*OpenAIGatewayService.forwardAsChatCompletions",
			file:        "backend/internal/service/openai_gateway_chat_completions.go",
			wantPersona: "codex-cli",
			wantSink:    "codex.responses.chat_completions",
		},
		{
			name:        "image URL backfill download",
			function:    "*OpenAIGatewayService.fetchOpenAIImageURLBase64",
			file:        "backend/internal/service/openai_images_b64_backfill.go",
			wantPersona: "out-of-scope",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, ok := classify(SinkRecord{Func: tc.function, File: tc.file})
			if !ok {
				t.Fatalf("新增发送点未登记：%s", tc.function)
			}
			if rule.persona != tc.wantPersona {
				t.Fatalf("persona=%q，期望 %q", rule.persona, tc.wantPersona)
			}
			if tc.wantSink != "" && rule.runtimeSinkID != tc.wantSink {
				t.Fatalf("runtime sink=%q，期望 %q", rule.runtimeSinkID, tc.wantSink)
			}
		})
	}
}
