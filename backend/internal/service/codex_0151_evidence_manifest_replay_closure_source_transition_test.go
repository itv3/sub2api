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

const codex0151EvidenceManifestReplayClosureServicePath = "docs/egress/maintenance/codex-cli-0151-evidence-manifest-replay-closure-source-transition.json"

var (
	codex0151EvidenceManifestReplayClosureServiceOnce   sync.Once
	codex0151EvidenceManifestReplayClosureServiceCached codex0151ToolReadinessReceiptService
	codex0151EvidenceManifestReplayClosureServiceErr    error
)

func loadCodex0151EvidenceManifestReplayClosureService() (codex0151ToolReadinessReceiptService, error) {
	codex0151EvidenceManifestReplayClosureServiceOnce.Do(func() {
		codex0151EvidenceManifestReplayClosureServiceCached, codex0151EvidenceManifestReplayClosureServiceErr =
			readCodex0151EvidenceManifestReplayClosureService()
	})
	return codex0151EvidenceManifestReplayClosureServiceCached, codex0151EvidenceManifestReplayClosureServiceErr
}

func readCodex0151EvidenceManifestReplayClosureService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(codex0151EvidenceManifestReplayClosureServicePath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 manifest 重放闭合 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 manifest 重放闭合 transition 自摘要不一致")
	}
	if err := validateCodex0151EvidenceManifestReplayClosureService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151EvidenceManifestReplayClosureService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-evidence-manifest-replay-closure-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-09-01T07:36:20Z" ||
		receipt.BaseCommit != "70c3144882b706c0aadcff9e0858e3372324e68b" ||
		receipt.Scope != "codex-cli-0.151-evidence-manifest-replay-closure" ||
		receipt.Result != "passed_codex_cli_0151_evidence_manifest_replay_closure" {
		return errors.New("Codex CLI 0.151 manifest 重放闭合 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_evidence_manifest_order_recovery" ||
		receipt.Predecessor.Path != codex0151EvidenceManifestOrderRecoveryServicePath {
		return errors.New("Codex CLI 0.151 manifest 重放闭合 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 manifest 重放闭合 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(EvidenceManifestReplayClosure|EvidenceManifestOrderRecovery|ManagedScenarioRecovery|FrameworkClarification|EvaluationRecovery)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 manifest 重放闭合 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 manifest 重放闭合 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_evaluation_recovery_source_transition_test.go": "fa1f8582cfa96d09d094c112f515502f766e25e0f9ee2ae2bfb3aa2ce0f719c5",
		"backend/internal/service/codex_0151_evaluation_recovery_source_transition_test.go":        "1168a0a0fbf475649251f9bb4d8dbe6476bf686c494d0cd37a4483b58475f7e9",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                 "ec71ba5605953f9b4584032efe595cc2fbb7aca062d0148846643cd5ca54b8ac",
		"docs/OFFICIAL_CLIENT_EMULATION_FRAMEWORK.md":                                              "6ab93d7f3aa01f5c14163cf3c2a13004951a8b53b24dce4bc36457567d3aee58",
		"tools/official_client_capture/codex_upgrade.py":                                           "9388177d89a380b9a0d6e3fa575a00ec60393e796a60658bfe9249359017a72e",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                "848ce51843cf6076c8730530887a64a33f5b0a7f6778f18c559ae37ea5a40fa8",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_evidence_manifest_replay_closure_source_transition_test.go": {},
		"backend/internal/service/codex_0151_evidence_manifest_replay_closure_source_transition_test.go":        {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 manifest 重放闭合 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		if readErr != nil || (upstreamMergeFrameworkServiceDigest(current) != transition.ToSHA256 &&
			!codex0151CurrentSourceDigestAcceptedService(
				transition.Path,
				transition.ToSHA256,
				upstreamMergeFrameworkServiceDigest(current),
			)) {
			return errors.New("Codex CLI 0.151 manifest 重放闭合 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 manifest 重放闭合 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		if readErr != nil || (upstreamMergeFrameworkServiceDigest(current) != addition.SHA256 &&
			!codex0151CurrentSourceDigestAcceptedService(
				addition.Path,
				addition.SHA256,
				upstreamMergeFrameworkServiceDigest(current),
			)) {
			return errors.New("Codex CLI 0.151 manifest 重放闭合 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 manifest 重放闭合路径闭集非法")
	}
	return nil
}

func codex0151EvidenceManifestReplayClosureSupersedesService(path, priorDigest, currentDigest string) bool {
	if codex0151CurrentSourceDigestAcceptedService(path, priorDigest, currentDigest) {
		return true
	}
	receipt, err := loadCodex0151EvidenceManifestReplayClosureService()
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

func TestCodex0151EvidenceManifestReplayClosureSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151EvidenceManifestReplayClosureService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151EvidenceManifestReplayClosureSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151EvidenceManifestReplayClosureService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151EvidenceManifestReplayClosureService(mutated); err == nil {
		t.Fatal("变异后的 Codex CLI 0.151 manifest 重放闭合 transition 被错误接受")
	}
}
