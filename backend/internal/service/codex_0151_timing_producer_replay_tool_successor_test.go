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

const codex0151TimingProducerReplayToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-timing-producer-replay-tool-successor-source-transition.json"

var (
	codex0151TimingProducerReplayToolSuccessorServiceOnce   sync.Once
	codex0151TimingProducerReplayToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151TimingProducerReplayToolSuccessorServiceErr    error
)

func loadCodex0151TimingProducerReplayToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151TimingProducerReplayToolSuccessorServiceOnce.Do(func() {
		codex0151TimingProducerReplayToolSuccessorServiceCached, codex0151TimingProducerReplayToolSuccessorServiceErr =
			readCodex0151TimingProducerReplayToolSuccessorService()
	})
	return codex0151TimingProducerReplayToolSuccessorServiceCached, codex0151TimingProducerReplayToolSuccessorServiceErr
}

func readCodex0151TimingProducerReplayToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151TimingProducerReplayToolSuccessorServicePath),
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
	if upstreamMergeFrameworkServiceDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151TimingProducerReplayToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151TimingProducerReplayToolSuccessorService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-timing-producer-replay-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T17:23:00Z" ||
		receipt.BaseCommit != "990c26f955fde57817fe1e0e98862d01c3ec5f7d" ||
		receipt.Scope != "codex-cli-0.151-timing-producer-replay-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_timing_producer_replay_tool_successor" {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_container_path_recovery_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151ContainerPathRecoveryToolSuccessorServicePath {
		return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(receipt.Predecessor.Path),
	))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
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
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 计时生产者重放工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedesService(
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
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 计时生产者重放工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedesService(
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

// codex0151TimingProducerReplayToolSuccessorSupersedesService 只承接计时生产者重放工具后继的精确摘要边。
func codex0151TimingProducerReplayToolSuccessorSupersedesService(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151TimingProducerReplayToolSuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedesService(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151TimingProducerReplayToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151TimingProducerReplayToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151TimingProducerReplayToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151TimingProducerReplayToolSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*codex0151ToolReadinessReceiptService)
	}{
		{
			name: "路径摘要漂移",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), mutated.Transitions...)
				mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "安全边界放宽",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Safety.OnlineAcceptancePerformed = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Additions = append([]openAIReplayOOMRepairAdditionService(nil), mutated.Additions[1:]...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151TimingProducerReplayToolSuccessorService(mutated); err == nil {
				t.Fatal("变异后的计时生产者重放工具后继 transition 被错误接受")
			}
		})
	}
}

const codex0151ManagedExecutionRootRecoveryToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-managed-execution-root-recovery-tool-successor-source-transition.json"

var (
	codex0151ManagedExecutionRootRecoveryToolSuccessorServiceOnce   sync.Once
	codex0151ManagedExecutionRootRecoveryToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151ManagedExecutionRootRecoveryToolSuccessorServiceErr    error
)

func loadCodex0151ManagedExecutionRootRecoveryToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151ManagedExecutionRootRecoveryToolSuccessorServiceOnce.Do(func() {
		codex0151ManagedExecutionRootRecoveryToolSuccessorServiceCached,
			codex0151ManagedExecutionRootRecoveryToolSuccessorServiceErr =
			readCodex0151ManagedExecutionRootRecoveryToolSuccessorService()
	})
	return codex0151ManagedExecutionRootRecoveryToolSuccessorServiceCached,
		codex0151ManagedExecutionRootRecoveryToolSuccessorServiceErr
}

func readCodex0151ManagedExecutionRootRecoveryToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151ManagedExecutionRootRecoveryToolSuccessorServicePath),
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
	if upstreamMergeFrameworkServiceDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151ManagedExecutionRootRecoveryToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151ManagedExecutionRootRecoveryToolSuccessorService(
	receipt codex0151ToolReadinessReceiptService,
) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-managed-execution-root-recovery-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T17:49:00Z" ||
		receipt.BaseCommit != "172491ba7dec907be06ff5ccf28b91f7b5402494" ||
		receipt.Scope != "codex-cli-0.151-managed-execution-root-recovery-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_managed_execution_root_recovery_tool_successor" {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_timing_producer_replay_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151TimingProducerReplayToolSuccessorServicePath {
		return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(receipt.Predecessor.Path),
	))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
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
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151BwrapZstdReadinessToolSuccessorSupersedesService(
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
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 受管执行根恢复工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(current) != addition.SHA256 {
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

// codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedesService 只承接受管执行根恢复工具后继的精确摘要边。
func codex0151ManagedExecutionRootRecoveryToolSuccessorSupersedesService(
	path,
	priorDigest,
	currentDigest string,
) bool {
	if codex0151CurrentSourceDigestAcceptedService(path, priorDigest, currentDigest) {
		return true
	}
	receipt, err := loadCodex0151ManagedExecutionRootRecoveryToolSuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151BwrapZstdReadinessToolSuccessorSupersedesService(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151BwrapZstdReadinessToolSuccessorSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151ManagedExecutionRootRecoveryToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151ManagedExecutionRootRecoveryToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151ManagedExecutionRootRecoveryToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151ManagedExecutionRootRecoveryToolSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*codex0151ToolReadinessReceiptService)
	}{
		{
			name: "路径摘要漂移",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), mutated.Transitions...)
				mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "安全边界放宽",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Safety.LiveAccountUsed = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append(
					[]openAIReplayOOMRepairTransitionService(nil),
					mutated.Transitions[1:]...,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151ManagedExecutionRootRecoveryToolSuccessorService(mutated); err == nil {
				t.Fatal("变异后的受管执行根恢复工具后继 transition 被错误接受")
			}
		})
	}
}

const codex0151BwrapZstdReadinessToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-bwrap-zstd-readiness-tool-successor-source-transition.json"

var (
	codex0151BwrapZstdReadinessToolSuccessorServiceOnce   sync.Once
	codex0151BwrapZstdReadinessToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151BwrapZstdReadinessToolSuccessorServiceErr    error
)

func loadCodex0151BwrapZstdReadinessToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151BwrapZstdReadinessToolSuccessorServiceOnce.Do(func() {
		codex0151BwrapZstdReadinessToolSuccessorServiceCached,
			codex0151BwrapZstdReadinessToolSuccessorServiceErr =
			readCodex0151BwrapZstdReadinessToolSuccessorService()
	})
	return codex0151BwrapZstdReadinessToolSuccessorServiceCached,
		codex0151BwrapZstdReadinessToolSuccessorServiceErr
}

func readCodex0151BwrapZstdReadinessToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151BwrapZstdReadinessToolSuccessorServicePath),
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
	if upstreamMergeFrameworkServiceDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151BwrapZstdReadinessToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151BwrapZstdReadinessToolSuccessorService(
	receipt codex0151ToolReadinessReceiptService,
) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-bwrap-zstd-readiness-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T19:04:00Z" ||
		receipt.BaseCommit != "816e9482ddc4271bb1a734aa39805dead225b1c3" ||
		receipt.Scope != "codex-cli-0.151-bwrap-zstd-readiness-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_bwrap_zstd_readiness_tool_successor" {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_managed_execution_root_recovery_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151ManagedExecutionRootRecoveryToolSuccessorServicePath {
		return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(receipt.Predecessor.Path),
	))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
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
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151C2PAJobIdentityToolSuccessorSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 bubblewrap 与 zstd 就绪工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151C2PAJobIdentityToolSuccessorSupersedesService(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
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

// codex0151BwrapZstdReadinessToolSuccessorSupersedesService 只承接 bubblewrap 与 zstd 就绪工具后继的精确摘要边。
func codex0151BwrapZstdReadinessToolSuccessorSupersedesService(
	path,
	priorDigest,
	currentDigest string,
) bool {
	receipt, err := loadCodex0151BwrapZstdReadinessToolSuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151C2PAJobIdentityToolSuccessorSupersedesService(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151C2PAJobIdentityToolSuccessorSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151BwrapZstdReadinessToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151BwrapZstdReadinessToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151BwrapZstdReadinessToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151BwrapZstdReadinessToolSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*codex0151ToolReadinessReceiptService)
	}{
		{
			name: "路径摘要漂移",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), mutated.Transitions...)
				mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "安全边界放宽",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Safety.ProductionConfigChanged = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append(
					[]openAIReplayOOMRepairTransitionService(nil),
					mutated.Transitions[1:]...,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151BwrapZstdReadinessToolSuccessorService(mutated); err == nil {
				t.Fatal("变异后的 bubblewrap 与 zstd 就绪工具后继 transition 被错误接受")
			}
		})
	}
}

const codex0151C2PAJobIdentityToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-c2pa-job-identity-tool-successor-source-transition.json"

var (
	codex0151C2PAJobIdentityToolSuccessorServiceOnce   sync.Once
	codex0151C2PAJobIdentityToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151C2PAJobIdentityToolSuccessorServiceErr    error
)

func loadCodex0151C2PAJobIdentityToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151C2PAJobIdentityToolSuccessorServiceOnce.Do(func() {
		codex0151C2PAJobIdentityToolSuccessorServiceCached,
			codex0151C2PAJobIdentityToolSuccessorServiceErr =
			readCodex0151C2PAJobIdentityToolSuccessorService()
	})
	return codex0151C2PAJobIdentityToolSuccessorServiceCached,
		codex0151C2PAJobIdentityToolSuccessorServiceErr
}

func readCodex0151C2PAJobIdentityToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151C2PAJobIdentityToolSuccessorServicePath),
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
		return receipt, errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151C2PAJobIdentityToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151C2PAJobIdentityToolSuccessorService(
	receipt codex0151ToolReadinessReceiptService,
) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-c2pa-job-identity-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T20:52:00Z" ||
		receipt.BaseCommit != "e1ff1ca1538ba63ed94cdfffe62bc7b04e05f4ba" ||
		receipt.Scope != "codex-cli-0.151-c2pa-job-identity-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_c2pa_job_identity_tool_successor" {
		return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_bwrap_zstd_readiness_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151BwrapZstdReadinessToolSuccessorServicePath {
		return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(receipt.Predecessor.Path),
	))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_timing_producer_replay_tool_successor_test.go": "40945c2e36d42603c101bfec29879218f0ccd5a149cb3a472a796a1d5e443880",
		"backend/internal/service/codex_0151_timing_producer_replay_tool_successor_test.go":        "115ad29ed834426e749ca23e1c8520ae5ce3beef90f4657da21b3f6fb1ef8904",
		"tools/official_client_capture/codex_upgrade_scenarios_0_151_0.json":                       "8903c9138487b65f3b42959965e68b4c99ce9bfc6f283e9ac2151d300d3a0274",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                "5d7f299b7019f154b68d65c1dd36e7c4e708848b68d6b71aaebdfd1b89ed03e3",
	}
	expectedAdditions := map[string]struct{}{
		"docs/egress/maintenance/codex-cli-0151-c2pa-job-identity-tool-successor/plan.json": {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151FullJobReadinessToolSuccessorSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 C2PA Job 身份工具后继路径闭集非法")
	}
	return nil
}

// codex0151C2PAJobIdentityToolSuccessorSupersedesService 只承接 C2PA Job 身份工具后继的精确摘要边。
func codex0151C2PAJobIdentityToolSuccessorSupersedesService(
	path,
	priorDigest,
	currentDigest string,
) bool {
	receipt, err := loadCodex0151C2PAJobIdentityToolSuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			transition.ToSHA256 == currentDigest {
			return true
		}
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			codex0151FullJobReadinessToolSuccessorSupersedesService(
				path,
				transition.ToSHA256,
				currentDigest,
			) {
			return true
		}
	}
	return codex0151FullJobReadinessToolSuccessorSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151C2PAJobIdentityToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151C2PAJobIdentityToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151C2PAJobIdentityToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151C2PAJobIdentityToolSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*codex0151ToolReadinessReceiptService)
	}{
		{
			name: "路径摘要漂移",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), mutated.Transitions...)
				mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "安全边界放宽",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Safety.LiveAccountUsed = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append(
					[]openAIReplayOOMRepairTransitionService(nil),
					mutated.Transitions[1:]...,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151C2PAJobIdentityToolSuccessorService(mutated); err == nil {
				t.Fatal("变异后的 C2PA Job 身份工具后继 transition 被错误接受")
			}
		})
	}
}

const codex0151FullJobReadinessToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-full-job-readiness-tool-successor-source-transition.json"

var (
	codex0151FullJobReadinessToolSuccessorServiceOnce   sync.Once
	codex0151FullJobReadinessToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151FullJobReadinessToolSuccessorServiceErr    error
)

func loadCodex0151FullJobReadinessToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151FullJobReadinessToolSuccessorServiceOnce.Do(func() {
		codex0151FullJobReadinessToolSuccessorServiceCached,
			codex0151FullJobReadinessToolSuccessorServiceErr =
			readCodex0151FullJobReadinessToolSuccessorService()
	})
	return codex0151FullJobReadinessToolSuccessorServiceCached,
		codex0151FullJobReadinessToolSuccessorServiceErr
}

func readCodex0151FullJobReadinessToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151FullJobReadinessToolSuccessorServicePath),
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
		return receipt, errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151FullJobReadinessToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151FullJobReadinessToolSuccessorService(
	receipt codex0151ToolReadinessReceiptService,
) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-full-job-readiness-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T22:53:31Z" ||
		receipt.BaseCommit != "e70ea7e0f9bc2aaafafec67c9b03c3e0cb480fd0" ||
		receipt.Scope != "codex-cli-0.151-full-job-readiness-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_full_job_readiness_tool_successor" {
		return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_c2pa_job_identity_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151C2PAJobIdentityToolSuccessorServicePath {
		return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(receipt.Predecessor.Path),
	))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_timing_producer_replay_tool_successor_test.go": "15acea27b2d780d0b80ae03871b35015537c1e1fb0d8027afbdd7c8f1911001a",
		"backend/internal/service/codex_0151_timing_producer_replay_tool_successor_test.go":        "df2042041bf2657ef5ffe2f9b9f7307327356506fc0e04024741f9b8868aeeaf",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                 "25eefc5ff46abb6723550629d18f5f7b5bb42e360a48f3305a8b407d19393cfb",
		"tools/official_client_capture/codex_upgrade.py":                                           "085e06e89aa9e9885974c84d278c81f6e4e0b2a2992c9a1c9b2e3c2e15d54fbe",
		"tools/official_client_capture/codex_upgrade_campaign.schema.json":                         "33df7ddd141b5f1bd527624ed26ccf89fb13a95afb57576412a8c2bf2d794e8b",
		"tools/official_client_capture/tests/control_receipt_fixtures.py":                          "e1dea353094b45d38360491a5d4d7d5ada65b13aa69f03827a452e0e16712df3",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                "1e9742f3953e625792264da1b74c910479765b047c61e2c3a7d0756fabbc943b",
	}
	expectedAdditions := map[string]struct{}{
		"docs/egress/maintenance/codex-cli-0151-full-job-readiness/plan.json":             {},
		"tools/official_client_capture/codex_upgrade_job_rehearsal_receipt.py":            {},
		"tools/official_client_capture/codex_upgrade_job_rehearsal_receipt.schema.json":   {},
		"tools/official_client_capture/tests/test_codex_upgrade_job_rehearsal_receipt.py": {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151EvidenceLabelPreflightToolSuccessorSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151EvidenceLabelPreflightToolSuccessorSupersedesService(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 完整 Job 就绪工具后继路径闭集非法")
	}
	return nil
}

// codex0151FullJobReadinessToolSuccessorSupersedesService 只承接完整 Job 就绪工具后继的精确摘要边。
func codex0151FullJobReadinessToolSuccessorSupersedesService(
	path,
	priorDigest,
	currentDigest string,
) bool {
	receipt, err := loadCodex0151FullJobReadinessToolSuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			transition.ToSHA256 == currentDigest {
			return true
		}
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			codex0151EvidenceLabelPreflightToolSuccessorSupersedesService(
				path,
				transition.ToSHA256,
				currentDigest,
			) {
			return true
		}
	}
	return codex0151EvidenceLabelPreflightToolSuccessorSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151FullJobReadinessToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151FullJobReadinessToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151FullJobReadinessToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151FullJobReadinessToolSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*codex0151ToolReadinessReceiptService)
	}{
		{
			name: "路径摘要漂移",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), mutated.Transitions...)
				mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "安全边界放宽",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Safety.LiveAccountUsed = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Additions = append(
					[]openAIReplayOOMRepairAdditionService(nil),
					mutated.Additions[1:]...,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151FullJobReadinessToolSuccessorService(mutated); err == nil {
				t.Fatal("变异后的完整 Job 就绪工具后继 transition 被错误接受")
			}
		})
	}
}

const codex0151EvidenceLabelPreflightToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-evidence-label-preflight-tool-successor-source-transition.json"

var (
	codex0151EvidenceLabelPreflightToolSuccessorServiceOnce   sync.Once
	codex0151EvidenceLabelPreflightToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151EvidenceLabelPreflightToolSuccessorServiceErr    error
)

func loadCodex0151EvidenceLabelPreflightToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151EvidenceLabelPreflightToolSuccessorServiceOnce.Do(func() {
		codex0151EvidenceLabelPreflightToolSuccessorServiceCached,
			codex0151EvidenceLabelPreflightToolSuccessorServiceErr =
			readCodex0151EvidenceLabelPreflightToolSuccessorService()
	})
	return codex0151EvidenceLabelPreflightToolSuccessorServiceCached,
		codex0151EvidenceLabelPreflightToolSuccessorServiceErr
}

func readCodex0151EvidenceLabelPreflightToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151EvidenceLabelPreflightToolSuccessorServicePath),
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
		return receipt, errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151EvidenceLabelPreflightToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151EvidenceLabelPreflightToolSuccessorService(
	receipt codex0151ToolReadinessReceiptService,
) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-evidence-label-preflight-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T00:21:53Z" ||
		receipt.BaseCommit != "556ea788f1ecc5c54847e8c49ac7546a779ba348" ||
		receipt.Scope != "codex-cli-0.151-evidence-label-preflight-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_evidence_label_preflight_tool_successor" {
		return errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_full_job_readiness_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151FullJobReadinessToolSuccessorServicePath {
		return errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(receipt.Predecessor.Path),
	))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_timing_producer_replay_tool_successor_test.go": "583b633b924d7b4043956a549ba79d06aeb9f6c65555b2603b7d59c564b902bd",
		"backend/internal/service/codex_0151_timing_producer_replay_tool_successor_test.go":        "24f0c77983a5d0a749d29a5e40a07d68e23021cb6183dab37bb63813b1b260ea",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                 "5eb3541c0cade2736e79657f205d41c2d2002d4f5c8fb125c53e98005aabd3d5",
		"tools/official_client_capture/codex_upgrade_job_rehearsal_receipt.py":                     "c72128c2594c043d3c347ca237cc8e3ed6c8fbce107ca43494fa9b76b7622020",
		"tools/official_client_capture/codex_upgrade_job_rehearsal_receipt.schema.json":            "c9613e0d0a31d8fde3fc5b215c19e88343e1193588e905974edfb4377a39c2cd",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                                "f104aeef4fff9181925903fbedb708ad9683e61e56184295b44999316ed8df8e",
		"tools/official_client_capture/tests/test_codex_upgrade_job_rehearsal_receipt.py":          "2d2e6f18baf53992b71b8ff917a3df3a2a71ce2298a9e4697ae3f7cba16b7472",
	}
	expectedAdditions := map[string]struct{}{
		"docs/egress/maintenance/codex-cli-0151-evidence-label-preflight-tool-successor/plan.json": {},
		"tools/official_client_capture/codex_upgrade_evidence_labels_0_151_0.json":                 {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		currentDigest := upstreamMergeFrameworkServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151SystemProxyCaptureToolSuccessorSupersedesService(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 证据标签前置工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 证据标签前置工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 证据标签前置工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 证据标签前置工具后继路径闭集非法")
	}
	return nil
}

// codex0151EvidenceLabelPreflightToolSuccessorSupersedesService 只承接证据标签前置工具后继的精确摘要边。
func codex0151EvidenceLabelPreflightToolSuccessorSupersedesService(
	path,
	priorDigest,
	currentDigest string,
) bool {
	receipt, err := loadCodex0151EvidenceLabelPreflightToolSuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest {
			if transition.ToSHA256 == currentDigest {
				return true
			}
			return codex0151SystemProxyCaptureToolSuccessorSupersedesService(
				path,
				transition.ToSHA256,
				currentDigest,
			)
		}
	}
	return codex0151SystemProxyCaptureToolSuccessorSupersedesService(
		path,
		priorDigest,
		currentDigest,
	)
}

func TestCodex0151EvidenceLabelPreflightToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151EvidenceLabelPreflightToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151EvidenceLabelPreflightToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151EvidenceLabelPreflightToolSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*codex0151ToolReadinessReceiptService)
	}{
		{
			name: "路径摘要漂移",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Transitions = append([]openAIReplayOOMRepairTransitionService(nil), mutated.Transitions...)
				mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
			},
		},
		{
			name: "安全边界放宽",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Safety.LiveAccountUsed = true
			},
		},
		{
			name: "闭集缺项",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Additions = append(
					[]openAIReplayOOMRepairAdditionService(nil),
					mutated.Additions[1:]...,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151EvidenceLabelPreflightToolSuccessorService(mutated); err == nil {
				t.Fatal("变异后的证据标签前置工具后继 transition 被错误接受")
			}
		})
	}
}
