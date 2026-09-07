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

const codex0151R9CandidateReadinessSourceTransitionServicePath = "docs/egress/maintenance/codex-cli-0151-r9-candidate-readiness-source-transition.json"

var (
	codex0151R9CandidateReadinessSourceTransitionServiceOnce   sync.Once
	codex0151R9CandidateReadinessSourceTransitionServiceCached codex0151ToolReadinessReceiptService
	codex0151R9CandidateReadinessSourceTransitionServiceErr    error
)

func loadCodex0151R9CandidateReadinessSourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	codex0151R9CandidateReadinessSourceTransitionServiceOnce.Do(func() {
		codex0151R9CandidateReadinessSourceTransitionServiceCached,
			codex0151R9CandidateReadinessSourceTransitionServiceErr =
			readCodex0151R9CandidateReadinessSourceTransitionService()
	})
	return codex0151R9CandidateReadinessSourceTransitionServiceCached,
		codex0151R9CandidateReadinessSourceTransitionServiceErr
}

func readCodex0151R9CandidateReadinessSourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(codex0151R9CandidateReadinessSourceTransitionServicePath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 r9 候选就绪 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 r9 候选就绪 transition 自摘要不一致")
	}
	if err := validateCodex0151R9CandidateReadinessSourceTransitionService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151R9CandidateReadinessSourceTransitionService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-r9-candidate-readiness-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T08:39:46Z" ||
		receipt.BaseCommit != "43649e951c64f19fd349f43965996b1b7ef73f69" ||
		receipt.Scope != "codex-cli-0.151-r9-candidate-readiness" ||
		receipt.Result != "passed_codex_cli_0151_r9_candidate_readiness" {
		return errors.New("Codex CLI 0.151 r9 候选就绪 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_historical_rehearsal_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151HistoricalRehearsalSuccessorSourceTransitionServicePath {
		return errors.New("Codex CLI 0.151 r9 候选就绪 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 r9 候选就绪 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_candidate_admin_credential_preflight tools.official_client_capture.tests.test_codex_upgrade_arm64_environment_receipt",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(R9CandidateReadiness|HistoricalRehearsalSuccessor)' -count=1",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 r9 候选就绪 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 r9 候选就绪 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/catalogdata/runtime/release-catalog.json":                            "55aef2c5b6c11ff646f8a276cf176d243cb813243a4bc57687de82b54f1ddb82",
		"backend/internal/officialegress/codex_0151_historical_rehearsal_successor_source_transition_test.go": "3e5f245882082035c42d39702f79b320b12df37c2125223270cbb5e4d8af58ac",
		"backend/internal/officialegress/releasecontract/testdata/release-graph.json":                         "14b8b4a1e52e69aaf3625cff5a89b81ce2f3cd4b39b8f1416911b72f00a38815",
		"backend/internal/service/codex_0151_historical_rehearsal_successor_source_transition_test.go":        "bb1c2960602e3dc4f4302c0d29ecffc5bc6c03f99abe718f516574c6209a6d82",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                            "6205099f4d6a50e8bac392ec09d9368d43d82e7b8f0ea39773d04947c7c013cf",
		"tools/official_client_capture/codex_upgrade.py":                                                      "4f411eb90e141a2706ac2ad69e5b145a44f3ebb300b0597947ad18dbe232fa8f",
		"tools/official_client_capture/codex_upgrade_arm64_environment_receipt.py":                            "97b96fcd9e341dc7ecff4c0359b12723dae747ec2f4bc9c0138a5bf8f6769d15",
		"tools/official_client_capture/codex_upgrade_arm64_environment_receipt.schema.json":                   "b0cb9dbe48e38e241c365d9745d21756dab4b701ccc2716e20c8bfbe4864aa6d",
		"tools/official_client_capture/tests/test_codex_upgrade_arm64_environment_receipt.py":                 "bf9a0d2c3187fe254be65665a21fe91205c38ab3a9cd1993b75f7aa80ca3bdc9",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/catalogdata/runtime/release-graphs/bce35dba2d095f74ee4357bf93b0f356f5b785aeab23dd725a3d4df9f8506dad.json": {},
		"backend/internal/officialegress/codex_0151_r9_candidate_readiness_source_transition_test.go":                                              {},
		"backend/internal/service/codex_0151_r9_candidate_readiness_source_transition_test.go":                                                     {},
		"docs/egress/maintenance/codex-cli-0151-r9-candidate-readiness/plan.json":                                                                  {},
		"tools/official_client_capture/tests/test_candidate_admin_credential_preflight.py":                                                         {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 r9 候选就绪 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151Arm64EnvironmentProducerReplayToolSuccessorSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 r9 候选就绪 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 r9 候选就绪 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151Arm64EnvironmentProducerReplayToolSuccessorSupersedesService(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 r9 候选就绪 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 r9 候选就绪 transition 路径闭集非法")
	}
	return nil
}

func codex0151R9CandidateReadinessSourceTransitionSupersedesService(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151R9CandidateReadinessSourceTransitionService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151Arm64EnvironmentProducerReplayToolSuccessorSupersedesService(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151Arm64EnvironmentProducerReplayToolSuccessorSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151R9CandidateReadinessSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151R9CandidateReadinessSourceTransitionService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151R9CandidateReadinessSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151R9CandidateReadinessSourceTransitionService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151R9CandidateReadinessSourceTransitionService(mutated); err == nil {
		t.Fatal("变异后的 r9 候选就绪 transition 被错误接受")
	}
}
