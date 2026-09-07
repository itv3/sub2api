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

const codex0151ContainerPathRecoveryToolSuccessorPath = "docs/egress/maintenance/codex-cli-0151-container-path-recovery-tool-successor-source-transition.json"

var (
	codex0151ContainerPathRecoveryToolSuccessorOnce   sync.Once
	codex0151ContainerPathRecoveryToolSuccessorCached codex0151ToolReadinessReceipt
	codex0151ContainerPathRecoveryToolSuccessorErr    error
)

func loadCodex0151ContainerPathRecoveryToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	codex0151ContainerPathRecoveryToolSuccessorOnce.Do(func() {
		codex0151ContainerPathRecoveryToolSuccessorCached, codex0151ContainerPathRecoveryToolSuccessorErr =
			readCodex0151ContainerPathRecoveryToolSuccessor()
	})
	return codex0151ContainerPathRecoveryToolSuccessorCached, codex0151ContainerPathRecoveryToolSuccessorErr
}

func readCodex0151ContainerPathRecoveryToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151ContainerPathRecoveryToolSuccessorPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151ContainerPathRecoveryToolSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151ContainerPathRecoveryToolSuccessor(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-container-path-recovery-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T17:02:00Z" ||
		receipt.BaseCommit != "432a4dfb9dc612b0343ed217b8dace587698fc37" ||
		receipt.Scope != "codex-cli-0.151-container-path-recovery-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_container_path_recovery_tool_successor" {
		return errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_model_policy_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151ModelPolicyToolSuccessorPath {
		return errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_01491_terminal_state_test.go":             "997e4fab24374ab80c46d4f0e91e5f7f580f02cf4f02f1f089174162196d9278",
		"backend/internal/officialegress/codex_0151_model_policy_tool_successor_test.go": "c1f9ea41f1d9d2a320929d485e4f2e0ea79a554bc118de104973d17667e99440",
		"backend/internal/service/codex_01491_terminal_state_test.go":                    "d5f16d2aa0a9a5adb76deb6c1c0671921148fc33cf9ccbaca1653f22586c20df",
		"backend/internal/service/codex_0151_model_policy_tool_successor_test.go":        "84057e4904cbcbea1aedfb734ce8ac844e076ddac100627d41850f5b79aacc0e",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                       "67b9c7bcbc2e585e76eb7c5b34514a5bf42769e014fa211041945610f21313c7",
		"tools/official_client_capture/codex_upgrade_scenarios_0_151_0.json":             "314e7f36a3569efbd51bf6f5feab740d448c25942e6ab541c1d318ba22c3b843",
		"tools/official_client_capture/codex_upgrade_timing_ledger.py":                   "f28f2527e6496a20af0377f00febf7c40f1b1d673a3d149f9797c899c257b8ee",
		"tools/official_client_capture/tests/test_codex_upgrade_timing_ledger.py":        "ad807e15799182d954bd7898fcf1b9cdee5d8389322d59938db9b2903214b0d7",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_container_path_recovery_tool_successor_test.go": {},
		"backend/internal/service/codex_0151_container_path_recovery_tool_successor_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-container-path-recovery-tool-successor/plan.json":   {},
		"tools/official_client_capture/tests/test_codex_0151_container_paths.py":                    {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151TimingProducerReplayToolSuccessorSupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 容器路径恢复工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!receiptSHA256(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 容器路径恢复工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151TimingProducerReplayToolSuccessorSupersedes(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 容器路径恢复工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 容器路径恢复工具后继路径闭集非法")
	}
	return nil
}

// codex0151ContainerPathRecoveryToolSuccessorSupersedes 只承接容器路径恢复工具后继的精确摘要边。
func codex0151ContainerPathRecoveryToolSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151ContainerPathRecoveryToolSuccessor()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151TimingProducerReplayToolSuccessorSupersedes(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151TimingProducerReplayToolSuccessorSupersedes(path, priorDigest, currentDigest)
}

func TestCodex0151ContainerPathRecoveryToolSuccessorSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151ContainerPathRecoveryToolSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151ContainerPathRecoveryToolSuccessorSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151ContainerPathRecoveryToolSuccessor()
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
				mutated.Safety.ProductionConfigChanged = true
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
			if err := validateCodex0151ContainerPathRecoveryToolSuccessor(mutated); err == nil {
				t.Fatal("变异后的容器路径恢复工具后继 transition 被错误接受")
			}
		})
	}
}
