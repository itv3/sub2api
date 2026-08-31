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

const codex0151StoppedLedgerRecoverySourceTransitionPath = "docs/egress/maintenance/codex-cli-0151-stopped-ledger-recovery-source-transition.json"

var (
	codex0151StoppedLedgerRecoverySourceTransitionOnce   sync.Once
	codex0151StoppedLedgerRecoverySourceTransitionCached codex0151ToolReadinessReceipt
	codex0151StoppedLedgerRecoverySourceTransitionErr    error
)

func loadCodex0151StoppedLedgerRecoverySourceTransition() (codex0151ToolReadinessReceipt, error) {
	codex0151StoppedLedgerRecoverySourceTransitionOnce.Do(func() {
		codex0151StoppedLedgerRecoverySourceTransitionCached,
			codex0151StoppedLedgerRecoverySourceTransitionErr =
			readCodex0151StoppedLedgerRecoverySourceTransition()
	})
	return codex0151StoppedLedgerRecoverySourceTransitionCached,
		codex0151StoppedLedgerRecoverySourceTransitionErr
}

func readCodex0151StoppedLedgerRecoverySourceTransition() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151StoppedLedgerRecoverySourceTransitionPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 自摘要不一致")
	}
	if err := validateCodex0151StoppedLedgerRecoverySourceTransition(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151StoppedLedgerRecoverySourceTransition(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-stopped-ledger-recovery-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T06:03:23Z" ||
		receipt.BaseCommit != "1e9fd6dee680d393e9116407657a7d63dac80e89" ||
		receipt.Scope != "codex-cli-0.151-stopped-ledger-recovery" ||
		receipt.Result != "passed_codex_cli_0151_stopped_ledger_recovery" {
		return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_arm64_typescript_dependency_source_transition" ||
		receipt.Predecessor.Path != codex0151Arm64TypescriptDependencySourceTransitionPath ||
		receipt.Predecessor.SHA256 != "8c831db2f33016adbc820e23384fb29b3f7599d80e642ee5add70199e312964d" {
		return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade tools.official_client_capture.tests.test_codex_upgrade_timing_ledger tools.official_client_capture.tests.test_codex_upgrade_job_rehearsal_receipt",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(StoppedLedgerRecovery|Arm64TypescriptDependency)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_arm64_typescript_dependency_source_transition_test.go": "2bd5b745ce91290050670e0d29896b7d9be70d0ada509f0ff0997059efd4941e",
		"backend/internal/service/codex_0151_arm64_typescript_dependency_source_transition_test.go":        "9ec557844b6404ec71f6d603087010182b07d24b0022b2df5a5c74e106c63c8c",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                         "58a94e545deaae489c1b7fc562c9b3eff50f53783ab7461e98d23bb838c30890",
		"docs/OFFICIAL_CLIENT_EMULATION_FRAMEWORK.md":                                                      "c326a4e43f04692dace778410cc95f155687dab80d577231a18955be100ce9d4",
		"tools/official_client_capture/codex_upgrade.py":                                                   "ac9d51ce5fa01bc067371f5cf1198b6290eb241438c0b35d00b4fb08bfe1f585",
		"tools/official_client_capture/tests/control_receipt_fixtures.py":                                  "0e139cd8f5a61a4d89e483dbd5bc59a0d11759d171192b1ddf3406b9dc156c8b",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                        "b4a1d1183d383e1316a5466ecf380b27784619eb9b15d9365cef3dcbad46cc7a",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_stopped_ledger_recovery_source_transition_test.go": {},
		"backend/internal/service/codex_0151_stopped_ledger_recovery_source_transition_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-stopped-ledger-recovery/plan.json":                     {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151DeterministicPackageFixtureSourceTransitionSupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !receiptSHA256(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 停线 Ledger 恢复 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151DeterministicPackageFixtureSourceTransitionSupersedes(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 停线 Ledger 恢复 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 停线 Ledger 恢复 transition 路径闭集非法")
	}
	return nil
}

func codex0151StoppedLedgerRecoverySourceTransitionSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151StoppedLedgerRecoverySourceTransition()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151DeterministicPackageFixtureSourceTransitionSupersedes(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151DeterministicPackageFixtureSourceTransitionSupersedes(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151StoppedLedgerRecoverySourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151StoppedLedgerRecoverySourceTransition(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151StoppedLedgerRecoverySourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151StoppedLedgerRecoverySourceTransition()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151StoppedLedgerRecoverySourceTransition(mutated); err == nil {
		t.Fatal("变异后的停线 Ledger 恢复 transition 被错误接受")
	}
}
