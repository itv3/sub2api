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
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
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
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedes(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
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
			(transition.ToSHA256 == currentDigest ||
				codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedes(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedes(
		path,
		priorDigest,
		currentDigest,
	)
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

const codex0151ManagedExecutionRootRecoveryToolSuccessorPath = "docs/egress/maintenance/codex-cli-0151-managed-execution-root-recovery-tool-successor-source-transition.json"

var (
	codex0151ManagedExecutionRootRecoveryToolSuccessorOnce   sync.Once
	codex0151ManagedExecutionRootRecoveryToolSuccessorCached codex0151ToolReadinessReceipt
	codex0151ManagedExecutionRootRecoveryToolSuccessorErr    error
)

func loadCodex0151ManagedExecutionRootRecoveryToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	codex0151ManagedExecutionRootRecoveryToolSuccessorOnce.Do(func() {
		codex0151ManagedExecutionRootRecoveryToolSuccessorCached, codex0151ManagedExecutionRootRecoveryToolSuccessorErr =
			readCodex0151ManagedExecutionRootRecoveryToolSuccessor()
	})
	return codex0151ManagedExecutionRootRecoveryToolSuccessorCached,
		codex0151ManagedExecutionRootRecoveryToolSuccessorErr
}

func readCodex0151ManagedExecutionRootRecoveryToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151ManagedExecutionRootRecoveryToolSuccessorPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151ManagedExecutionRootRecoveryToolSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151ManagedExecutionRootRecoveryToolSuccessor(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-managed-execution-root-recovery-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T17:49:00Z" ||
		receipt.BaseCommit != "172491ba7dec907be06ff5ccf28b91f7b5402494" ||
		receipt.Scope != "codex-cli-0.151-managed-execution-root-recovery-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_managed_execution_root_recovery_tool_successor" {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_timing_producer_replay_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151TimingProducerReplayToolSuccessorPath ||
		receipt.Predecessor.SHA256 != "0897f6b11e02a86f072852b199cd0c8ed050233d322f116591cc6ee2d530567e" {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_timing_producer_replay_tool_successor_test.go": "1156f91b30044ae9f80ba1abdca9d98d5ff3a21ae674ddaf545aa9564596e045",
		"backend/internal/service/codex_0151_timing_producer_replay_tool_successor_test.go":        "57661d60f18e8d7a0b80c9c7bb78a253da68f91d492c2b052c7b7892360acf0c",
		"tools/official_client_capture/run_h1_wire_probe.sh":                                       "043e29d0bde9fcefea323b9db4028920b638308dc689e56dbca3135c12862957",
		"tools/official_client_capture/run_images_wire_probe.sh":                                   "3fe235e1843ad50d561cda2a347ef01ba90b02b09800a91e5b7c1a3d3e938a13",
		"tools/official_client_capture/run_official_codex_compact_capture.sh":                      "8e6eae6c46d0a0cb141bb5381474461709c906394b7b50d6da01ffa13e8a6591",
		"tools/official_client_capture/run_official_http_fallback_baseline.sh":                     "ba2cb97a3e81956393947f942e93261bf8603a0291faad147154a040802cf10d",
		"tools/official_client_capture/run_official_relay_scenario.sh":                             "fed7e44ccabb844c597b56be64788c0e4662bf86e5e0fa043b2f55396df6c57b",
		"tools/official_client_capture/run_sub2api_direct_matrix.sh":                               "45b5d9cf24c6b7c92e2b8bc8a6b2ac9459b2696d265aaeeb45fff052c7214567",
		"tools/official_client_capture/run_sub2api_openai_mitm_matrix.sh":                          "337f5d775ffbe6535acf279cb71ab72462013385248e9a03f81f974ebbc9ec8a",
		"tools/official_client_capture/tests/test_codex_0151_container_paths.py":                   "9b762128b696d14b987be1fe2b512b452288d609aff420aa94ee9494621a9e33",
	}
	expectedAdditions := map[string]struct{}{
		"docs/egress/maintenance/codex-cli-0151-managed-execution-root-recovery-tool-successor/plan.json": {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151BwrapZstdReadinessToolSuccessorSupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!receiptSHA256(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继路径闭集非法")
	}
	return nil
}

// codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedes 只承接受管执行根恢复工具后继的精确摘要边。
func codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151ManagedExecutionRootRecoveryToolSuccessor()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151BwrapZstdReadinessToolSuccessorSupersedes(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151BwrapZstdReadinessToolSuccessorSupersedes(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151ManagedExecutionRootRecoveryToolSuccessorSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151ManagedExecutionRootRecoveryToolSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151ManagedExecutionRootRecoveryToolSuccessorSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151ManagedExecutionRootRecoveryToolSuccessor()
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
				mutated.Safety.LiveAccountUsed = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceipt) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), mutated.Transitions[1:]...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151ManagedExecutionRootRecoveryToolSuccessor(mutated); err == nil {
				t.Fatal("变异后的受管执行根恢复工具后继 transition 被错误接受")
			}
		})
	}
}

const codex0151BwrapZstdReadinessToolSuccessorPath = "docs/egress/maintenance/codex-cli-0151-bwrap-zstd-readiness-tool-successor-source-transition.json"

var (
	codex0151BwrapZstdReadinessToolSuccessorOnce   sync.Once
	codex0151BwrapZstdReadinessToolSuccessorCached codex0151ToolReadinessReceipt
	codex0151BwrapZstdReadinessToolSuccessorErr    error
)

func loadCodex0151BwrapZstdReadinessToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	codex0151BwrapZstdReadinessToolSuccessorOnce.Do(func() {
		codex0151BwrapZstdReadinessToolSuccessorCached, codex0151BwrapZstdReadinessToolSuccessorErr =
			readCodex0151BwrapZstdReadinessToolSuccessor()
	})
	return codex0151BwrapZstdReadinessToolSuccessorCached,
		codex0151BwrapZstdReadinessToolSuccessorErr
}

func readCodex0151BwrapZstdReadinessToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151BwrapZstdReadinessToolSuccessorPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151BwrapZstdReadinessToolSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151BwrapZstdReadinessToolSuccessor(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-bwrap-zstd-readiness-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T19:04:00Z" ||
		receipt.BaseCommit != "816e9482ddc4271bb1a734aa39805dead225b1c3" ||
		receipt.Scope != "codex-cli-0.151-bwrap-zstd-readiness-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_bwrap_zstd_readiness_tool_successor" {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_managed_execution_root_recovery_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151ManagedExecutionRootRecoveryToolSuccessorPath ||
		receipt.Predecessor.SHA256 != "134598773ebb343593f272dd39945cdf8a2ddeb6813d42333628fc4e65e7a081" {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_timing_producer_replay_tool_successor_test.go": "72709e18c8ddc7015bb56ba38fff30ec3f2d82ec444c74f0de46b113690fa350",
		"backend/internal/service/codex_0151_timing_producer_replay_tool_successor_test.go":        "4a47ffc141b4653ad1122a17338d0f877419ededbb9abe252994690bc00ed161",
		"tools/official_client_capture/codex_upgrade.py":                                           "93fdecaec04ba6e92fb1b55008faa55b263f739413c38defa5a9e248d1c08bb2",
		"tools/official_client_capture/model_condition_receipts.py":                                "61f0610f35229e4b2d4269e72eb4533b5e65b3a3a05bc24ad0207170660f95f1",
		"tools/official_client_capture/relay_extract.py":                                           "d9dd06bc1183865e9f9c1ebd891d6d1068c294eca8d5a19abb4c7413c60d2de0",
		"tools/official_client_capture/runtime_image/README.md":                                    "2762b9fb89e2df3d24c49f54e4b2559e0acb517c0971891d6112dd8fd634ab9a",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                "07e83941855530c71fc548a93662a73e99bb2745113338e5d284b08ab7803606",
		"tools/official_client_capture/tests/test_model_condition_receipt.py":                      "ab8024e23a59af9aee25215a3d65893f699d5ac2a078192fdbca14bf47f737df",
	}
	expectedAdditions := map[string]struct{}{
		"docs/egress/maintenance/codex-cli-0151-bwrap-zstd-readiness-tool-successor/plan.json": {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != transition.ToSHA256 {
			return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!receiptSHA256(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继路径闭集非法")
	}
	return nil
}

// codex0151BwrapZstdReadinessToolSuccessorSupersedes 只承接 bubblewrap 与 zstd 就绪工具后继的精确摘要边。
func codex0151BwrapZstdReadinessToolSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151BwrapZstdReadinessToolSuccessor()
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

func TestCodex0151BwrapZstdReadinessToolSuccessorSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151BwrapZstdReadinessToolSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151BwrapZstdReadinessToolSuccessorSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151BwrapZstdReadinessToolSuccessor()
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
				mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), mutated.Transitions[1:]...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151BwrapZstdReadinessToolSuccessor(mutated); err == nil {
				t.Fatal("变异后的 bubblewrap 与 zstd 就绪工具后继 transition 被错误接受")
			}
		})
	}
}
