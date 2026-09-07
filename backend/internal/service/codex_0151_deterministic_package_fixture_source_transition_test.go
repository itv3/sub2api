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

const codex0151DeterministicPackageFixtureSourceTransitionServicePath = "docs/egress/maintenance/codex-cli-0151-deterministic-package-fixture-source-transition.json"

var (
	codex0151DeterministicPackageFixtureSourceTransitionServiceOnce   sync.Once
	codex0151DeterministicPackageFixtureSourceTransitionServiceCached codex0151ToolReadinessReceiptService
	codex0151DeterministicPackageFixtureSourceTransitionServiceErr    error
)

func loadCodex0151DeterministicPackageFixtureSourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	codex0151DeterministicPackageFixtureSourceTransitionServiceOnce.Do(func() {
		codex0151DeterministicPackageFixtureSourceTransitionServiceCached,
			codex0151DeterministicPackageFixtureSourceTransitionServiceErr =
			readCodex0151DeterministicPackageFixtureSourceTransitionService()
	})
	return codex0151DeterministicPackageFixtureSourceTransitionServiceCached,
		codex0151DeterministicPackageFixtureSourceTransitionServiceErr
}

func readCodex0151DeterministicPackageFixtureSourceTransitionService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(codex0151DeterministicPackageFixtureSourceTransitionServicePath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 确定性包夹具 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 确定性包夹具 transition 自摘要不一致")
	}
	if err := validateCodex0151DeterministicPackageFixtureSourceTransitionService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151DeterministicPackageFixtureSourceTransitionService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-deterministic-package-fixture-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T06:20:54Z" ||
		receipt.BaseCommit != "9ef01aee9105a66bc61f03f886392119c64ec147" ||
		receipt.Scope != "codex-cli-0.151-deterministic-package-fixture" ||
		receipt.Result != "passed_codex_cli_0151_deterministic_package_fixture" {
		return errors.New("Codex CLI 0.151 确定性包夹具 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_stopped_ledger_recovery_source_transition" ||
		receipt.Predecessor.Path != codex0151StoppedLedgerRecoverySourceTransitionServicePath {
		return errors.New("Codex CLI 0.151 确定性包夹具 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 确定性包夹具 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade.CodexUpgradeTest.test_campaign_fixture_package_is_independent_of_wall_clock tools.official_client_capture.tests.test_codex_upgrade.CodexUpgradeTest.test_successor_rebinds_controls_after_predecessor_ledger_stops",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(DeterministicPackageFixture|StoppedLedgerRecovery)' -count=1",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 确定性包夹具 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 确定性包夹具 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_stopped_ledger_recovery_source_transition_test.go": "b0500ed0780f3d6110935943615ce4162d5835100be3afc7486972f1bbfa86e1",
		"backend/internal/service/codex_0151_stopped_ledger_recovery_source_transition_test.go":        "512f8162c5ecec8de00ac1552e8d52c6c5f191741c2a8cf03b3eb40586fcae12",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                    "a4074100b278b817a6c20a2c6859435649f250c64aee11f0d6ac423b37da39bf",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_deterministic_package_fixture_source_transition_test.go": {},
		"backend/internal/service/codex_0151_deterministic_package_fixture_source_transition_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-deterministic-package-fixture/plan.json":                     {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 确定性包夹具 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151HistoricalRehearsalSuccessorSourceTransitionSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 确定性包夹具 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 确定性包夹具 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151HistoricalRehearsalSuccessorSourceTransitionSupersedesService(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 确定性包夹具 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 确定性包夹具 transition 路径闭集非法")
	}
	return nil
}

func codex0151DeterministicPackageFixtureSourceTransitionSupersedesService(path, priorDigest, currentDigest string) bool {
	if codex0151CurrentSourceDigestAcceptedService(path, priorDigest, currentDigest) {
		return true
	}
	receipt, err := loadCodex0151DeterministicPackageFixtureSourceTransitionService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151HistoricalRehearsalSuccessorSourceTransitionSupersedesService(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151HistoricalRehearsalSuccessorSourceTransitionSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151DeterministicPackageFixtureSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151DeterministicPackageFixtureSourceTransitionService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151DeterministicPackageFixtureSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151DeterministicPackageFixtureSourceTransitionService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151DeterministicPackageFixtureSourceTransitionService(mutated); err == nil {
		t.Fatal("变异后的确定性包夹具 transition 被错误接受")
	}
}
