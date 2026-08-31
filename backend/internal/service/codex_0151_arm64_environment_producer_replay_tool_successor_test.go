package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

const codex0151Arm64EnvironmentProducerReplayToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-arm64-environment-producer-replay-tool-successor-source-transition.json"

var (
	codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceOnce   sync.Once
	codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceErr    error
)

func loadCodex0151Arm64EnvironmentProducerReplayToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceOnce.Do(func() {
		codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceCached,
			codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceErr =
			readCodex0151Arm64EnvironmentProducerReplayToolSuccessorService()
	})
	return codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceCached,
		codex0151Arm64EnvironmentProducerReplayToolSuccessorServiceErr
}

func readCodex0151Arm64EnvironmentProducerReplayToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151Arm64EnvironmentProducerReplayToolSuccessorServicePath),
	))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 尾部存在额外 JSON")
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
	if upstreamMergeFrameworkServiceDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151Arm64EnvironmentProducerReplayToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151Arm64EnvironmentProducerReplayToolSuccessorService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-arm64-environment-producer-replay-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T09:35:22Z" ||
		receipt.BaseCommit != "102d91678cd2e003bceca115ccfd968cad87721a" ||
		receipt.Scope != "codex-cli-0.151-arm64-environment-producer-replay-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_arm64_environment_producer_replay_tool_successor" {
		return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_r9_candidate_readiness_source_transition" ||
		receipt.Predecessor.Path != codex0151R9CandidateReadinessSourceTransitionServicePath ||
		receipt.Predecessor.SHA256 != "7c2fd13e6b0c87305bab379ad2d68b073c6f181d0e7e1a45d04fb3e02aa4aa25" {
		return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade_arm64_environment_receipt",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(Arm64EnvironmentProducerReplayToolSuccessor|R9CandidateReadiness)' -count=1",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_r9_candidate_readiness_source_transition_test.go": "aa6ba46b26991aeb81313a4a287b31557463188c9f8806a8cb0963404b797df1",
		"backend/internal/service/codex_0151_r9_candidate_readiness_source_transition_test.go":        "0e28360690fbdefb3d8247e6e6a6e4dce3227842b81961fc662ea0fcfdb690f5",
		"docs/OFFICIAL_CLIENT_EMULATION_FRAMEWORK.md":                                                 "d053fb4841683e372da3b24961f9be0ba30c57cf85178a6d468ae13bb6e1c9e2",
		"tools/official_client_capture/codex_upgrade_arm64_environment_receipt.py":                    "7633ad1f101a8320126fb6c76417362bf8571faed9f14e5dcf20ec616a593048",
		"tools/official_client_capture/tests/test_codex_upgrade_arm64_environment_receipt.py":         "85702d076edb93cd6e9230343f6b7a585a24529bcf9ff0926f3eb0edb1560d61",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_arm64_environment_producer_replay_tool_successor_test.go": {},
		"backend/internal/service/codex_0151_arm64_environment_producer_replay_tool_successor_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-arm64-environment-producer-replay-tool-successor/plan.json":   {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(current) != transition.ToSHA256 {
			return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 ARM64 环境 producer 重放工具后继路径闭集非法")
	}
	return nil
}

// codex0151Arm64EnvironmentProducerReplayToolSuccessorSupersedesService 只承接本次精确摘要边。
func codex0151Arm64EnvironmentProducerReplayToolSuccessorSupersedesService(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151Arm64EnvironmentProducerReplayToolSuccessorService()
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

func TestCodex0151Arm64EnvironmentProducerReplayToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151Arm64EnvironmentProducerReplayToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151Arm64EnvironmentProducerReplayToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151Arm64EnvironmentProducerReplayToolSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151Arm64EnvironmentProducerReplayToolSuccessorService(mutated); err == nil {
		t.Fatal("变异后的 ARM64 环境 producer 重放工具后继 transition 被错误接受")
	}
}
