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

const codex0151HistoricalRehearsalSuccessorSourceTransitionServicePath = "docs/egress/maintenance/codex-cli-0151-historical-rehearsal-successor-source-transition.json"

var (
	codex0151HistoricalRehearsalSuccessorSourceTransitionServiceOnce   sync.Once
	codex0151HistoricalRehearsalSuccessorSourceTransitionServiceCached codex0151ToolReadinessReceiptService
	codex0151HistoricalRehearsalSuccessorSourceTransitionServiceErr    error
)

func loadCodex0151HistoricalRehearsalSuccessorSourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	codex0151HistoricalRehearsalSuccessorSourceTransitionServiceOnce.Do(func() {
		codex0151HistoricalRehearsalSuccessorSourceTransitionServiceCached,
			codex0151HistoricalRehearsalSuccessorSourceTransitionServiceErr =
			readCodex0151HistoricalRehearsalSuccessorSourceTransitionService()
	})
	return codex0151HistoricalRehearsalSuccessorSourceTransitionServiceCached,
		codex0151HistoricalRehearsalSuccessorSourceTransitionServiceErr
}

func readCodex0151HistoricalRehearsalSuccessorSourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(codex0151HistoricalRehearsalSuccessorSourceTransitionServicePath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 历史 rehearsal successor transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 历史 rehearsal successor transition 自摘要不一致")
	}
	if err := validateCodex0151HistoricalRehearsalSuccessorSourceTransitionService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151HistoricalRehearsalSuccessorSourceTransitionService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-historical-rehearsal-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T06:54:05Z" ||
		receipt.BaseCommit != "c79fa7e4ba033f760f06ce7ab9136d2aa94f40b8" ||
		receipt.Scope != "codex-cli-0.151-historical-rehearsal-successor" ||
		receipt.Result != "passed_codex_cli_0151_historical_rehearsal_successor" {
		return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_deterministic_package_fixture_source_transition" ||
		receipt.Predecessor.Path != codex0151DeterministicPackageFixtureSourceTransitionServicePath {
		return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade.CodexUpgradeTest.test_successor_rebinds_controls_after_predecessor_ledger_stops tools.official_client_capture.tests.test_codex_upgrade.CodexUpgradeTest.test_successor_rebinds_current_job_rehearsal_after_tool_change",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(HistoricalRehearsalSuccessor|DeterministicPackageFixture)' -count=1",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_deterministic_package_fixture_source_transition_test.go": "b92954e5b3466366808982c1e84de174a86b9ec9a2e40c3244835ab0e3375424",
		"backend/internal/service/codex_0151_deterministic_package_fixture_source_transition_test.go":        "dc66a00b49e893137f0e2b360896ce919448007bb30d406e1fe982671a912ddb",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                           "efeb347285ee3d3fa74fd7e3471455fcf3f0b92b52ad7f252d3709d8eacee9f1",
		"tools/official_client_capture/codex_upgrade.py":                                                     "955e61bc012e25575f8c93462a5fc988267736cc7a6cd886774ab92959a1ec1f",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                          "349b024d590e3d3f540e9fa0033027c95d76bfa08992ec0cb9e284c69dd80396",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_historical_rehearsal_successor_source_transition_test.go": {},
		"backend/internal/service/codex_0151_historical_rehearsal_successor_source_transition_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-historical-rehearsal-successor/plan.json":                     {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151R9CandidateReadinessSourceTransitionSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 历史 rehearsal successor addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151R9CandidateReadinessSourceTransitionSupersedesService(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 历史 rehearsal successor addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 历史 rehearsal successor transition 路径闭集非法")
	}
	return nil
}

func codex0151HistoricalRehearsalSuccessorSourceTransitionSupersedesService(path, priorDigest, currentDigest string) bool {
	if codex0151CurrentSourceDigestAcceptedService(path, priorDigest, currentDigest) {
		return true
	}
	receipt, err := loadCodex0151HistoricalRehearsalSuccessorSourceTransitionService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151R9CandidateReadinessSourceTransitionSupersedesService(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151R9CandidateReadinessSourceTransitionSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151HistoricalRehearsalSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151HistoricalRehearsalSuccessorSourceTransitionService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151HistoricalRehearsalSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151HistoricalRehearsalSuccessorSourceTransitionService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151HistoricalRehearsalSuccessorSourceTransitionService(mutated); err == nil {
		t.Fatal("变异后的历史 rehearsal successor transition 被错误接受")
	}
}
