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

const codex0151Arm64TypescriptDependencySourceTransitionServicePath = "docs/egress/maintenance/codex-cli-0151-arm64-typescript-dependency-source-transition.json"

var (
	codex0151Arm64TypescriptDependencySourceTransitionServiceOnce   sync.Once
	codex0151Arm64TypescriptDependencySourceTransitionServiceCached codex0151ToolReadinessReceiptService
	codex0151Arm64TypescriptDependencySourceTransitionServiceErr    error
)

func loadCodex0151Arm64TypescriptDependencySourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	codex0151Arm64TypescriptDependencySourceTransitionServiceOnce.Do(func() {
		codex0151Arm64TypescriptDependencySourceTransitionServiceCached,
			codex0151Arm64TypescriptDependencySourceTransitionServiceErr =
			readCodex0151Arm64TypescriptDependencySourceTransitionService()
	})
	return codex0151Arm64TypescriptDependencySourceTransitionServiceCached,
		codex0151Arm64TypescriptDependencySourceTransitionServiceErr
}

func readCodex0151Arm64TypescriptDependencySourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(codex0151Arm64TypescriptDependencySourceTransitionServicePath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 ARM64 TypeScript transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 ARM64 TypeScript transition 自摘要不一致")
	}
	if err := validateCodex0151Arm64TypescriptDependencySourceTransitionService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151Arm64TypescriptDependencySourceTransitionService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-arm64-typescript-dependency-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T05:40:05Z" ||
		receipt.BaseCommit != "4263d01750484a28d4771ea982de8227a98a40a9" ||
		receipt.Scope != "codex-cli-0.151-arm64-typescript-dependency" ||
		receipt.Result != "passed_codex_cli_0151_arm64_typescript_dependency" {
		return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_formal_recovery_source_transition" ||
		receipt.Predecessor.Path != codex0151FormalRecoverySourceTransitionServicePath {
		return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(Arm64TypescriptDependency|FormalRecovery)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"Makefile": "1bcb83eed48dbe0a5198f98e8fc3d59cf16d96bbb8292abe44cb540783f24462",
		"backend/internal/officialegress/codex_0151_formal_recovery_source_transition_test.go": "1ce77dc959b7621b690db2bb616d22fa60986a203b2ade581484481acb71f866",
		"backend/internal/service/codex_0151_formal_recovery_source_transition_test.go":        "5a8bb698c3f9d8de3fc91da910666a73ad60c19bf571b750958224fc7a780b1e",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                             "c2e3c1d420e2890bd0cf49529304dadb402b75019bda66fafb78487d781661b3",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_arm64_typescript_dependency_source_transition_test.go": {},
		"backend/internal/service/codex_0151_arm64_typescript_dependency_source_transition_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-arm64-typescript-dependency/plan.json":                     {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151StoppedLedgerRecoverySourceTransitionSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 ARM64 TypeScript addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151StoppedLedgerRecoverySourceTransitionSupersedesService(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 ARM64 TypeScript addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 ARM64 TypeScript transition 路径闭集非法")
	}
	return nil
}

func codex0151Arm64TypescriptDependencySourceTransitionSupersedesService(path, priorDigest, currentDigest string) bool {
	if codex0151CurrentSourceDigestAcceptedService(path, priorDigest, currentDigest) {
		return true
	}
	receipt, err := loadCodex0151Arm64TypescriptDependencySourceTransitionService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151StoppedLedgerRecoverySourceTransitionSupersedesService(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151StoppedLedgerRecoverySourceTransitionSupersedesService(path, priorDigest, currentDigest)
}

func TestCodex0151Arm64TypescriptDependencySourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151Arm64TypescriptDependencySourceTransitionService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151Arm64TypescriptDependencySourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151Arm64TypescriptDependencySourceTransitionService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151Arm64TypescriptDependencySourceTransitionService(mutated); err == nil {
		t.Fatal("变异后的 ARM64 TypeScript transition 被错误接受")
	}
}
