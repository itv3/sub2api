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

const codex0151TestTracePreflightToolSuccessorPath = "docs/egress/maintenance/codex-cli-0151-test-trace-preflight-tool-successor-source-transition.json"

var (
	codex0151TestTracePreflightToolSuccessorOnce   sync.Once
	codex0151TestTracePreflightToolSuccessorCached codex0151ToolReadinessReceipt
	codex0151TestTracePreflightToolSuccessorErr    error
)

func loadCodex0151TestTracePreflightToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	codex0151TestTracePreflightToolSuccessorOnce.Do(func() {
		codex0151TestTracePreflightToolSuccessorCached,
			codex0151TestTracePreflightToolSuccessorErr =
			readCodex0151TestTracePreflightToolSuccessor()
	})
	return codex0151TestTracePreflightToolSuccessorCached,
		codex0151TestTracePreflightToolSuccessorErr
}

func readCodex0151TestTracePreflightToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151TestTracePreflightToolSuccessorPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 test trace P0 后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 test trace P0 后继 transition 自摘要不一致")
	}
	if err := validateCodex0151TestTracePreflightToolSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151TestTracePreflightToolSuccessor(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-test-trace-preflight-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-31T13:37:55Z" ||
		receipt.BaseCommit != "4c495cd72d4abdb89c0d5073a2d4f3e68899eb31" ||
		receipt.Scope != "codex-cli-0.151-test-trace-preflight-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_test_trace_preflight_tool_successor" {
		return errors.New("Codex CLI 0.151 test trace P0 后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_arm64_environment_producer_replay_tool_successor" ||
		receipt.Predecessor.Path != codex0151Arm64EnvironmentProducerReplayToolSuccessorPath ||
		receipt.Predecessor.SHA256 != "217642ab257708b226e0fd71b4582643694ce834d22e4ffbbc5e0e00f6d13185" {
		return errors.New("Codex CLI 0.151 test trace P0 后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 test trace P0 后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest tools.official_client_capture.tests.test_candidate_test_trace",
		"go test ./internal/officialegress -run 'TestCodex0151(TestTracePreflightToolSuccessor|Arm64EnvironmentProducerReplayToolSuccessor)' -count=1",
		"make CAPTURE_TYPESCRIPT_MODULE=<locked-absolute-path> test-capture-tools",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 test trace P0 后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 test trace P0 后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_arm64_environment_producer_replay_tool_successor_test.go": "70ed5cb073b055aba50a4b21355740dbd4ad9f4918c4df3295fd53ebe35e8277",
		"docs/CODEX_CLI_CLIENT_EMULATION_GUIDE.md":                                                            "2db10a0bda73449cf5122a62c7c7e7da86d0cb2ad7dad21df6401c7c88472001",
		"tools/official_client_capture/candidate_test_fact_map_0_151_0.json":                                  "9bd4431ac4f099e6771e888c59fd27b0c2ff6a2e7eecf2ad7da74116136ad94e",
		"tools/official_client_capture/candidate_test_trace.py":                                               "b455754ff570ed963058b4f381de2cab0b56f958bb29cf49683c67b76a036a1e",
		"tools/official_client_capture/tests/test_candidate_test_trace.py":                                    "48df30afb6defecac81523d614e97abcd2eaab3ec0d675ad69f65777cb08ebb6",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_test_trace_preflight_tool_successor_test.go": {},
		"docs/egress/maintenance/codex-cli-0151-test-trace-preflight-tool-successor/plan.json":   {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 test trace P0 后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != transition.ToSHA256 {
			return errors.New("Codex CLI 0.151 test trace P0 后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !receiptSHA256(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 test trace P0 后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 test trace P0 后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) || len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 test trace P0 后继路径闭集非法")
	}
	return nil
}

func codex0151TestTracePreflightToolSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151TestTracePreflightToolSuccessor()
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

func TestCodex0151TestTracePreflightToolSuccessorSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151TestTracePreflightToolSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151TestTracePreflightToolSuccessorSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151TestTracePreflightToolSuccessor()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]openAIReplayOOMRepairTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateCodex0151TestTracePreflightToolSuccessor(mutated); err == nil {
		t.Fatal("变异后的 test trace P0 后继 transition 被错误接受")
	}
}
