package officialegress

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
)

const codex0151TimingProducerReplayToolSuccessorPath = "docs/egress/maintenance/codex-cli-0151-timing-producer-replay-tool-successor-source-transition.json"

var (
	codex0151TimingProducerReplayToolSuccessorOnce   sync.Once
	codex0151TimingProducerReplayToolSuccessorCached codex0151ToolReadinessReceipt
	codex0151TimingProducerReplayToolSuccessorErr    error
)

func loadCodex0151TimingProducerReplayToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	codex0151TimingProducerReplayToolSuccessorOnce.Do(func() {
		codex0151TimingProducerReplayToolSuccessorCached, codex0151TimingProducerReplayToolSuccessorErr =
			readCodex0151TimingProducerReplayToolSuccessor()
	})
	return codex0151TimingProducerReplayToolSuccessorCached, codex0151TimingProducerReplayToolSuccessorErr
}

func readCodex0151TimingProducerReplayToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151TimingProducerReplayToolSuccessorPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 尾部存在额外 JSON")
	}
	var identityDocument map[string]any
	if err := json.Unmarshal(raw, &identityDocument); err != nil {
		return receipt, err
	}
	delete(identityDocument, "identity_sha256")
	canonical, err := json.Marshal(identityDocument)
	if err != nil {
		return receipt, err
	}
	canonical = append(canonical, '\n')
	if upstreamMergeFrameworkDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151TimingProducerReplayToolSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151TimingProducerReplayToolSuccessor(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-timing-producer-replay-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T17:23:00Z" ||
		receipt.BaseCommit != "990c26f955fde57817fe1e0e98862d01c3ec5f7d" ||
		receipt.Scope != "codex-cli-0.151-timing-producer-replay-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_timing_producer_replay_tool_successor" {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_container_path_recovery_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151ContainerPathRecoveryToolSuccessorPath ||
		receipt.Predecessor.SHA256 != "8d6b2360010d5e27fe28dba999848974e1a45b425ab996a6f68f5c69cfbcfd17" {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_container_path_recovery_tool_successor_test.go": "8679f98b2c76494fef90903e193c7312b91ab69031c7af7ba4e82746154b7d83",
		"backend/internal/service/codex_0151_container_path_recovery_tool_successor_test.go":        "ad63813efa3f7059e46e30ed0fe3016a3db1eb73e9290ace58546a67da690505",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                  "d1ae527c8e0894e7adfef9ed2bafbd0127cd66961b6f2c45069ec0e57e806462",
		"tools/official_client_capture/codex_upgrade_timing_ledger.py":                              "6dab54cddaf94e4d481c20d47392a8a36ce35d5f0aa49f0c2c2ea6334b18de68",
		"tools/official_client_capture/tests/test_codex_upgrade_timing_ledger.py":                   "7329cd0f169742ba17874f29afe15a2c65d7396223aabe94d6082e5d7f2c051e",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_timing_producer_replay_tool_successor_test.go": {},
		"backend/internal/service/codex_0151_timing_producer_replay_tool_successor_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-timing-producer-replay-tool-successor/plan.json":   {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != transition.ToSHA256 {
			return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!receiptSHA256(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 计时生产者重放工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 计时生产者重放工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继路径闭集非法")
	}
	return nil
}

// codex0151TimingProducerReplayToolSuccessorSupersedes 只承接计时生产者重放工具后继的精确摘要边。
func codex0151TimingProducerReplayToolSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151TimingProducerReplayToolSuccessor()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			transition.ToSHA256 == currentDigest {
			return true
		}
	}
	return false
}

func TestCodex0151TimingProducerReplayToolSuccessorSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151TimingProducerReplayToolSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151TimingProducerReplayToolSuccessorSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151TimingProducerReplayToolSuccessor()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*codex0151ToolReadinessReceipt)
	}{
		{
			name: "路径摘要漂移",
			mutate: func(mutated *codex0151ToolReadinessReceipt) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), mutated.Transitions...)
				mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "安全边界放宽",
			mutate: func(mutated *codex0151ToolReadinessReceipt) {
				mutated.Safety.OnlineAcceptancePerformed = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceipt) {
				mutated.Additions = append([]openAIReplayOOMRepairAddition(nil), mutated.Additions[1:]...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151TimingProducerReplayToolSuccessor(mutated); err == nil {
				t.Fatal("变异后的计时生产者重放工具后继 transition 被错误接受")
			}
		})
	}
}
