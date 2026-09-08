package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIOfficialEgressWSToolOutputTurnTreatsToolHistoryBeforeUserAsHistorical(t *testing.T) {
	payload := map[string]any{
		"type": "response.create",
		"client_metadata": map[string]any{
			"turn_id": "11111111-1111-4111-8111-111111111111",
		},
		// 工具调用由助手产生但没有 role=assistant；后面的用户消息仍然
		// 是明确的新轮次边界，前面的调用与输出都应判为历史。
		"input": []any{
			map[string]any{"type": "function_call", "call_id": "call_old"},
			map[string]any{"type": "function_call_output", "call_id": "call_old", "output": "ok"},
			map[string]any{"type": "message", "role": "user", "content": "继续"},
		},
	}
	input, ok := payload["input"].([]any)
	require.True(t, ok)
	require.Equal(t, [][]int{{0, 1}, {2}}, splitOfficialOpenAIWSInputTurnSegments(input))

	hasAny, hasCurrent, reliable, err := classifyOfficialOpenAIWSToolOutputTurn(payload)
	require.NoError(t, err)
	require.True(t, hasAny)
	require.False(t, hasCurrent)
	require.True(t, reliable)
}

func TestOpenAIOfficialEgressWSToolOutputTurnFailsClosedWhenBoundaryIsAmbiguous(t *testing.T) {
	payload := map[string]any{
		"type": "response.create",
		"client_metadata": map[string]any{
			"turn_id": "11111111-1111-4111-8111-111111111111",
		},
		// 工具输出后只有无角色普通项，既没有逐项 turn_id，也没有新用户
		// 消息形成可信边界；该场景仍必须保持严格拒绝。
		"input": []any{
			map[string]any{"type": "function_call", "call_id": "call_ambiguous"},
			map[string]any{"type": "function_call_output", "call_id": "call_ambiguous", "output": "ok"},
			map[string]any{"type": "input_text", "text": "继续"},
		},
	}
	hasAny, hasCurrent, reliable, err := classifyOfficialOpenAIWSToolOutputTurn(payload)
	require.NoError(t, err)
	require.True(t, hasAny)
	require.False(t, hasCurrent)
	require.False(t, reliable)
}
