package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIOfficialEgressWSToolOutputTurnFailsClosedWhenBoundaryIsAmbiguous(t *testing.T) {
	payload := map[string]any{
		"type": "response.create",
		"client_metadata": map[string]any{
			"turn_id": "11111111-1111-4111-8111-111111111111",
		},
		// 没有逐项 turn_id，且同一分段混有 function_call 与 output；不能
		// 猜测 output 是否属于当前轮。
		"input": []any{
			map[string]any{"type": "function_call", "call_id": "call_old"},
			map[string]any{"type": "function_call_output", "call_id": "call_old", "output": "ok"},
			map[string]any{"type": "message", "role": "user", "content": "继续"},
		},
	}
	hasAny, hasCurrent, reliable, err := classifyOfficialOpenAIWSToolOutputTurn(payload)
	require.NoError(t, err)
	require.True(t, hasAny)
	require.False(t, hasCurrent)
	require.False(t, reliable)
}
