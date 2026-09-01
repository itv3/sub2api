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

const codex0151EvaluationRecoveryPath = "docs/egress/maintenance/codex-cli-0151-evaluation-recovery-source-transition.json"

var (
	codex0151EvaluationRecoveryOnce   sync.Once
	codex0151EvaluationRecoveryCached codex0151ToolReadinessReceipt
	codex0151EvaluationRecoveryErr    error
)

func loadCodex0151EvaluationRecovery() (codex0151ToolReadinessReceipt, error) {
	codex0151EvaluationRecoveryOnce.Do(func() {
		codex0151EvaluationRecoveryCached, codex0151EvaluationRecoveryErr =
			readCodex0151EvaluationRecovery()
	})
	return codex0151EvaluationRecoveryCached, codex0151EvaluationRecoveryErr
}

func readCodex0151EvaluationRecovery() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151EvaluationRecoveryPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 评估恢复 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 评估恢复 transition 自摘要不一致")
	}
	if err := validateCodex0151EvaluationRecovery(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151EvaluationRecovery(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-evaluation-recovery-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-09-01T05:07:25Z" ||
		receipt.BaseCommit != "35e895191789be7e1b7b295daea5a94b415362c1" ||
		receipt.Scope != "codex-cli-0.151-evaluation-recovery" ||
		receipt.Result != "passed_codex_cli_0151_evaluation_recovery" {
		return errors.New("Codex CLI 0.151 评估恢复 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_test_trace_preflight_tool_successor" ||
		receipt.Predecessor.Path != codex0151TestTracePreflightToolSuccessorPath ||
		receipt.Predecessor.SHA256 != "d8b7f1bf9b07b71be4d8e423c01c23447ebd744d539aa3a54e720b38b5b42f5e" {
		return errors.New("Codex CLI 0.151 评估恢复 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 评估恢复 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(EvaluationRecovery|TestTracePreflightToolSuccessor|Arm64EnvironmentProducerReplayToolSuccessor)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 评估恢复 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 评估恢复 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/catalog_generic_bind_retirement_test.go":                      "50942dcc21efef1cb808b7ab3ae13d5768b04f07c71282732f8fb0ac1e688d0e",
		"backend/internal/officialegress/catalog_retirements_test.go":                                  "c3e6e3261b7658e5da04953a1b7edf41ccc57a70478a5852902a34f08377503a",
		"backend/internal/officialegress/codex_0151_test_trace_preflight_tool_successor_test.go":       "7d4ac0d6919f29c0aefdd92c8a43fd8e8b2f6b4d768da6145d9b95d53914dd7c",
		"backend/internal/service/compatibility_code_retirement_closure_test.go":                       "9e7ba19d2a4dc810c660836e07da9a583f58e97ac7cf4a6ef7b7dd7093c323ad",
		"backend/internal/service/codex_0151_arm64_environment_producer_replay_tool_successor_test.go": "3dbb42cea9bf7fa3f99aacea7065e31289e73c1a8030362b5bf1815e6e3b84e7",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                     "c3348ad333f5add6b51755a004c93109b9c5b1263454ccec33af05fe8b7701e3",
		"docs/OFFICIAL_CLIENT_EMULATION_FRAMEWORK.md":                                                  "0b8f2adc69bc55c2efd75fee51624714b43f7bef5eb51b7319bfb0890f0df3b9",
		"tools/official_client_capture/codex_upgrade.py":                                               "40688af442fe2da95d4a81f7a0ac7b18ea6b3a3932f9d122c8e2b60fe9a01b81",
		"tools/official_client_capture/codex_upgrade_seal_preview.schema.json":                         "0160c1a05416cd7b3660404bb90add3098cbdd15b954c562baa3bc11deee0a76",
		"tools/official_client_capture/codex_upgrade_stage_result.schema.json":                         "fb7b63f3008850e24f19c15c02b9d990341aeae6b9a0da4ca36de24fb45fdb94",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                    "e8c97b5d40e991dc9600a9acd55c9e8ed6d6a66f8929d36f53f5c53740f59b46",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_evaluation_recovery_source_transition_test.go": {},
		"backend/internal/service/codex_0151_evaluation_recovery_source_transition_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-evaluation-recovery/plan.json":                     {},
		"tools/official_client_capture/codex_upgrade_evidence_manifest.py":                         {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 评估恢复 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151FrameworkClarificationSupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 评估恢复 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !receiptSHA256(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 评估恢复 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151FrameworkClarificationSupersedes(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 评估恢复 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 评估恢复路径闭集非法")
	}
	return nil
}

// codex0151EvaluationRecoverySupersedes 沿只追加前序链验证精确摘要可达性。
func codex0151EvaluationRecoverySupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151EvaluationRecovery()
	if err != nil {
		return false
	}
	receipts := []codex0151ToolReadinessReceipt{receipt}
	seen := map[string]struct{}{codex0151EvaluationRecoveryPath: {}}
	for {
		current := receipts[len(receipts)-1]
		predecessorPath := current.Predecessor.Path
		predecessorSHA256 := current.Predecessor.SHA256
		if predecessorPath == "" && predecessorSHA256 == "" {
			break
		}
		if predecessorPath == "" || !receiptSHA256(predecessorSHA256) || len(receipts) >= 64 {
			return false
		}
		if _, ok := seen[predecessorPath]; ok {
			return false
		}
		seen[predecessorPath] = struct{}{}
		raw, readErr := os.ReadFile(codex01491TerminalRepoPath(predecessorPath))
		if readErr != nil || upstreamMergeFrameworkDigest(raw) != predecessorSHA256 {
			return false
		}
		var predecessor codex0151ToolReadinessReceipt
		if json.Unmarshal(raw, &predecessor) != nil {
			return false
		}
		receipts = append(receipts, predecessor)
	}
	clarification, clarificationErr := loadCodex0151FrameworkClarification()
	if clarificationErr != nil {
		return false
	}
	receipts = append(receipts, clarification)
	managedScenarioRecovery, managedScenarioRecoveryErr :=
		loadCodex0151ManagedScenarioRecovery()
	if managedScenarioRecoveryErr != nil {
		return false
	}
	receipts = append(receipts, managedScenarioRecovery)
	manifestOrderRecovery, manifestOrderRecoveryErr :=
		loadCodex0151EvidenceManifestOrderRecovery()
	if manifestOrderRecoveryErr != nil {
		return false
	}
	receipts = append(receipts, manifestOrderRecovery)
	replayClosure, replayClosureErr := loadCodex0151EvidenceManifestReplayClosure()
	if replayClosureErr != nil {
		return false
	}
	receipts = append(receipts, replayClosure)
	reachable := map[string]struct{}{priorDigest: {}}
	for {
		changed := false
		for _, source := range receipts {
			for _, transition := range source.Transitions {
				if transition.Path != path || !receiptSHA256(transition.FromSHA256) ||
					!receiptSHA256(transition.ToSHA256) {
					continue
				}
				if _, ok := reachable[transition.FromSHA256]; !ok {
					continue
				}
				if _, ok := reachable[transition.ToSHA256]; !ok {
					reachable[transition.ToSHA256] = struct{}{}
					changed = true
				}
			}
		}
		if _, ok := reachable[currentDigest]; ok {
			return true
		}
		if !changed {
			return false
		}
	}
}

const codex0151FrameworkClarificationPath = "docs/egress/maintenance/codex-cli-0151-framework-clarification-source-transition.json"

var (
	codex0151FrameworkClarificationOnce   sync.Once
	codex0151FrameworkClarificationCached codex0151ToolReadinessReceipt
	codex0151FrameworkClarificationErr    error
)

func loadCodex0151FrameworkClarification() (codex0151ToolReadinessReceipt, error) {
	codex0151FrameworkClarificationOnce.Do(func() {
		codex0151FrameworkClarificationCached, codex0151FrameworkClarificationErr =
			readCodex0151FrameworkClarification()
	})
	return codex0151FrameworkClarificationCached, codex0151FrameworkClarificationErr
}

func readCodex0151FrameworkClarification() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151FrameworkClarificationPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 框架澄清 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 框架澄清 transition 自摘要不一致")
	}
	if err := validateCodex0151FrameworkClarification(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151FrameworkClarification(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-framework-clarification-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-09-01T06:10:28Z" ||
		receipt.BaseCommit != "a074d5c2ab9677347046e9a1fd48872769a65d54" ||
		receipt.Scope != "codex-cli-0.151-framework-clarification" ||
		receipt.Result != "passed_codex_cli_0151_framework_clarification" {
		return errors.New("Codex CLI 0.151 框架澄清 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_evaluation_recovery" ||
		receipt.Predecessor.Path != codex0151EvaluationRecoveryPath ||
		receipt.Predecessor.SHA256 != "470a65c98fe4d7ecd1684cb2cb4346cd353b56363c36847b914e20f6b3ab274c" {
		return errors.New("Codex CLI 0.151 框架澄清 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 框架澄清 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"git diff --check",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(FrameworkClarification|EvaluationRecovery)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 框架澄清 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 框架澄清 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_evaluation_recovery_source_transition_test.go": "0074ae9e33bdd83370885ebcd17f40733ca19aa416449f1e67e7dc767998093f",
		"backend/internal/service/codex_0151_evaluation_recovery_source_transition_test.go":        "a3dff98daf42daaecc1062ff287f09e0ac278ff16f935d7091009a9c923ebf88",
		"docs/OFFICIAL_CLIENT_EMULATION_FRAMEWORK.md":                                              "74dc01ac86f6f44c77a508bc5834fe3a6699e92d436d9d0701fe00952e556b75",
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 框架澄清 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151ManagedScenarioRecoverySupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 框架澄清 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != 0 ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) {
		return errors.New("Codex CLI 0.151 框架澄清路径闭集非法")
	}
	return nil
}

// codex0151FrameworkClarificationSupersedes 承接文档澄清及其直接工具后继。
func codex0151FrameworkClarificationSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151FrameworkClarification()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest {
			if transition.ToSHA256 == currentDigest {
				return true
			}
			return codex0151ManagedScenarioRecoverySupersedes(
				path,
				transition.ToSHA256,
				currentDigest,
			)
		}
	}
	return codex0151ManagedScenarioRecoverySupersedes(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151FrameworkClarificationSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151FrameworkClarification(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151FrameworkClarificationSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151FrameworkClarification()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151FrameworkClarification(mutated); err == nil {
		t.Fatal("变异后的 Codex CLI 0.151 框架澄清 transition 被错误接受")
	}
}

const codex0151ManagedScenarioRecoveryPath = "docs/egress/maintenance/codex-cli-0151-managed-scenario-recovery-source-transition.json"

var (
	codex0151ManagedScenarioRecoveryOnce   sync.Once
	codex0151ManagedScenarioRecoveryCached codex0151ToolReadinessReceipt
	codex0151ManagedScenarioRecoveryErr    error
)

func loadCodex0151ManagedScenarioRecovery() (codex0151ToolReadinessReceipt, error) {
	codex0151ManagedScenarioRecoveryOnce.Do(func() {
		codex0151ManagedScenarioRecoveryCached, codex0151ManagedScenarioRecoveryErr =
			readCodex0151ManagedScenarioRecovery()
	})
	return codex0151ManagedScenarioRecoveryCached, codex0151ManagedScenarioRecoveryErr
}

func readCodex0151ManagedScenarioRecovery() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151ManagedScenarioRecoveryPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 受管场景恢复 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 受管场景恢复 transition 自摘要不一致")
	}
	if err := validateCodex0151ManagedScenarioRecovery(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151ManagedScenarioRecovery(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-managed-scenario-recovery-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-09-01T06:26:28Z" ||
		receipt.BaseCommit != "28c4b8fb8dab7a29a77135d2e9c19e056f8abd27" ||
		receipt.Scope != "codex-cli-0.151-managed-scenario-recovery" ||
		receipt.Result != "passed_codex_cli_0151_managed_scenario_recovery" {
		return errors.New("Codex CLI 0.151 受管场景恢复 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_framework_clarification" ||
		receipt.Predecessor.Path != codex0151FrameworkClarificationPath ||
		receipt.Predecessor.SHA256 != "2113cb607bcf7f080036220767f6c2267506260e36992fc451d8b301eea1d0e6" {
		return errors.New("Codex CLI 0.151 受管场景恢复 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 受管场景恢复 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(ManagedScenarioRecovery|FrameworkClarification|EvaluationRecovery)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 受管场景恢复 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 受管场景恢复 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_evaluation_recovery_source_transition_test.go": "4895527ac689c4c07c1650407e8cbd7f613bd6030abdb35265f123a4a09db9c5",
		"backend/internal/service/codex_0151_evaluation_recovery_source_transition_test.go":        "460f77f12d9af03c30fbdacdf02cbb36f7ebd1c8ea24bf4ed01bbba15361cd61",
		"tools/official_client_capture/codex_upgrade.py":                                           "38fc19c54804ff7b106ccd6950522bb11bbca432cc93a88875ea3fe836c549ac",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                "15ffcbd6975fc0cbd798d893aa50ecd1ea428cdc10c0ff91b9fb490733eb8039",
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 受管场景恢复 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151EvidenceManifestOrderRecoverySupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 受管场景恢复 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != 0 ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) {
		return errors.New("Codex CLI 0.151 受管场景恢复路径闭集非法")
	}
	return nil
}

func codex0151ManagedScenarioRecoverySupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151ManagedScenarioRecovery()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest {
			if transition.ToSHA256 == currentDigest {
				return true
			}
			return codex0151EvidenceManifestOrderRecoverySupersedes(
				path,
				transition.ToSHA256,
				currentDigest,
			)
		}
	}
	return codex0151EvidenceManifestOrderRecoverySupersedes(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151ManagedScenarioRecoverySourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151ManagedScenarioRecovery(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151ManagedScenarioRecoverySourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151ManagedScenarioRecovery()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151ManagedScenarioRecovery(mutated); err == nil {
		t.Fatal("变异后的 Codex CLI 0.151 受管场景恢复 transition 被错误接受")
	}
}

const codex0151EvidenceManifestOrderRecoveryPath = "docs/egress/maintenance/codex-cli-0151-evidence-manifest-order-recovery-source-transition.json"

var (
	codex0151EvidenceManifestOrderRecoveryOnce   sync.Once
	codex0151EvidenceManifestOrderRecoveryCached codex0151ToolReadinessReceipt
	codex0151EvidenceManifestOrderRecoveryErr    error
)

func loadCodex0151EvidenceManifestOrderRecovery() (codex0151ToolReadinessReceipt, error) {
	codex0151EvidenceManifestOrderRecoveryOnce.Do(func() {
		codex0151EvidenceManifestOrderRecoveryCached, codex0151EvidenceManifestOrderRecoveryErr =
			readCodex0151EvidenceManifestOrderRecovery()
	})
	return codex0151EvidenceManifestOrderRecoveryCached, codex0151EvidenceManifestOrderRecoveryErr
}

func readCodex0151EvidenceManifestOrderRecovery() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151EvidenceManifestOrderRecoveryPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 manifest 排序恢复 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 manifest 排序恢复 transition 自摘要不一致")
	}
	if err := validateCodex0151EvidenceManifestOrderRecovery(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151EvidenceManifestOrderRecovery(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-evidence-manifest-order-recovery-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-09-01T07:03:57Z" ||
		receipt.BaseCommit != "ccd081841b7ee8f2e54feaf3d12db8fc9f0cc8dc" ||
		receipt.Scope != "codex-cli-0.151-evidence-manifest-order-recovery" ||
		receipt.Result != "passed_codex_cli_0151_evidence_manifest_order_recovery" {
		return errors.New("Codex CLI 0.151 manifest 排序恢复 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_managed_scenario_recovery" ||
		receipt.Predecessor.Path != codex0151ManagedScenarioRecoveryPath ||
		receipt.Predecessor.SHA256 != "a2ee0695c14773c9fa1af2f60e894378eecf6ba10389ec0f001c3761463e0b80" {
		return errors.New("Codex CLI 0.151 manifest 排序恢复 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 manifest 排序恢复 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_codex_upgrade",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex0151(EvidenceManifestOrderRecovery|ManagedScenarioRecovery|FrameworkClarification|EvaluationRecovery)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 manifest 排序恢复 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 manifest 排序恢复 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_evaluation_recovery_source_transition_test.go": "e77c7d8c822c1398ad56aab6880ca3b6da242bf0ca774a20a3f87c80715c7dfa",
		"backend/internal/service/codex_0151_evaluation_recovery_source_transition_test.go":        "44501edb62785ae0d84e73e8d896ed7d62f272e4a1037aea0e2d2799bc55ef43",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                 "41525a31943a65535800649b3972edea69d2d2496e0eec1af68a6d5face3275b",
		"docs/OFFICIAL_CLIENT_EMULATION_FRAMEWORK.md":                                              "23eae275384371ab00d5786b755110332e7f6159e955dd16bdee85b4b0097c9c",
		"tools/official_client_capture/codex_upgrade.py":                                           "6f65d94cd79cae8d04ca442c50c24337fd4bf2242dbb7f0f70d4f4499d32f35d",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                "7b405fba5ea25d38de899be90cf0e888ba19851a0c4c86f9bd5cb9dc457aabd4",
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 manifest 排序恢复 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151EvidenceManifestReplayClosureSupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 manifest 排序恢复 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != 0 ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) {
		return errors.New("Codex CLI 0.151 manifest 排序恢复路径闭集非法")
	}
	return nil
}

func codex0151EvidenceManifestOrderRecoverySupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151EvidenceManifestOrderRecovery()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest {
			if transition.ToSHA256 == currentDigest {
				return true
			}
			return codex0151EvidenceManifestReplayClosureSupersedes(
				path,
				transition.ToSHA256,
				currentDigest,
			)
		}
	}
	return codex0151EvidenceManifestReplayClosureSupersedes(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151EvidenceManifestOrderRecoverySourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151EvidenceManifestOrderRecovery(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151EvidenceManifestOrderRecoverySourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151EvidenceManifestOrderRecovery()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151EvidenceManifestOrderRecovery(mutated); err == nil {
		t.Fatal("变异后的 Codex CLI 0.151 manifest 排序恢复 transition 被错误接受")
	}
}

func TestCodex0151EvaluationRecoverySourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151EvaluationRecovery(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151EvaluationRecoverySourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151EvaluationRecovery()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151EvaluationRecovery(mutated); err == nil {
		t.Fatal("变异后的 Codex CLI 0.151 评估恢复 transition 被错误接受")
	}
}
