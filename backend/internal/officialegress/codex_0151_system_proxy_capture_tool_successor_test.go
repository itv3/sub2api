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

const codex0151SystemProxyCaptureToolSuccessorPath = "docs/egress/maintenance/codex-cli-0151-system-proxy-capture-tool-successor-source-transition.json"

var (
	codex0151SystemProxyCaptureToolSuccessorOnce   sync.Once
	codex0151SystemProxyCaptureToolSuccessorCached codex0151ToolReadinessReceipt
	codex0151SystemProxyCaptureToolSuccessorErr    error
)

func loadCodex0151SystemProxyCaptureToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	codex0151SystemProxyCaptureToolSuccessorOnce.Do(func() {
		codex0151SystemProxyCaptureToolSuccessorCached,
			codex0151SystemProxyCaptureToolSuccessorErr =
			readCodex0151SystemProxyCaptureToolSuccessor()
	})
	return codex0151SystemProxyCaptureToolSuccessorCached,
		codex0151SystemProxyCaptureToolSuccessorErr
}

func readCodex0151SystemProxyCaptureToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151SystemProxyCaptureToolSuccessorPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151SystemProxyCaptureToolSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151SystemProxyCaptureToolSuccessor(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-system-proxy-capture-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T01:48:13Z" ||
		receipt.BaseCommit != "e3cf0961b0f35f258a2a9cf8e57889240477388a" ||
		receipt.Scope != "codex-cli-0.151-system-proxy-capture-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_system_proxy_capture_tool_successor" {
		return errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_evidence_label_preflight_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151EvidenceLabelPreflightToolSuccessorPath ||
		receipt.Predecessor.SHA256 != "debd3ef1ba753d548190bdd0e8f62975c8f047a9eb0c4118ab42a6877cfb787e" {
		return errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_timing_producer_replay_tool_successor_test.go": "b001f4f22926765cd2ca918686f23801d0c44da677836c2180823abbc83fc11c",
		"backend/internal/service/codex_0151_timing_producer_replay_tool_successor_test.go":        "b3888319a829bdbf02953753dfb42eba8af63387af565fa581a6480a10445d11",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                 "fa0f44f5509e2d31c350f3b6ef893bafaadfaad35a55647c5e608161cc07b2ba",
		"docs/OFFICIAL_CLIENT_EMULATION_FRAMEWORK.md":                                              "6e9db8b6600c2b108bb7aef7d8b1c408c20c2448f26e2e45af4df7b6dc81f05a",
		"tools/official_client_capture/codex_upgrade_scenarios_0_151_0.json":                       "6ff00b0cc9d3388ce7b67733312a200b3a270eab98e5950d2f210618a2e928cb",
		"tools/official_client_capture/drive_codex_model_catalog.py":                               "0d7dc732143fcc7908c2f6c60cbd0228454a820a4663900d926a7755f83446ea",
		"tools/official_client_capture/tests/test_model_catalog_prewarm.py":                        "55ef9c9aff721356d687b57e551fe2b9cf6c5978596decca62e2afee0f9e2610",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_system_proxy_capture_tool_successor_test.go": {},
		"backend/internal/service/codex_0151_system_proxy_capture_tool_successor_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-system-proxy-capture-tool-successor/plan.json":   {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != transition.ToSHA256 {
			return errors.New("Codex CLI 0.151 系统代理取证工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!receiptSHA256(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 系统代理取证工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 系统代理取证工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 系统代理取证工具后继路径闭集非法")
	}
	return nil
}

func codex0151SystemProxyCaptureToolSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151SystemProxyCaptureToolSuccessor()
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

func TestCodex0151SystemProxyCaptureToolSuccessorSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151SystemProxyCaptureToolSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151SystemProxyCaptureToolSuccessorSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151SystemProxyCaptureToolSuccessor()
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
				mutated.Additions = mutated.Additions[1:]
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), receipt.Transitions...)
			mutated.Additions = append([]openAIReplayOOMRepairAddition(nil), receipt.Additions...)
			test.mutate(&mutated)
			if err := validateCodex0151SystemProxyCaptureToolSuccessor(mutated); err == nil {
				t.Fatal("变异后的系统代理取证工具后继 transition 被错误接受")
			}
		})
	}
}
