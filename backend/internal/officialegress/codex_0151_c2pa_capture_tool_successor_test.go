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

const codex0151C2PACaptureToolSuccessorPath = "docs/egress/maintenance/codex-cli-0151-c2pa-capture-tool-successor-source-transition.json"

var (
	codex0151C2PACaptureToolSuccessorOnce   sync.Once
	codex0151C2PACaptureToolSuccessorCached codex0151ToolReadinessReceipt
	codex0151C2PACaptureToolSuccessorErr    error
)

func loadCodex0151C2PACaptureToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	codex0151C2PACaptureToolSuccessorOnce.Do(func() {
		codex0151C2PACaptureToolSuccessorCached, codex0151C2PACaptureToolSuccessorErr =
			readCodex0151C2PACaptureToolSuccessor()
	})
	return codex0151C2PACaptureToolSuccessorCached, codex0151C2PACaptureToolSuccessorErr
}

func readCodex0151C2PACaptureToolSuccessor() (codex0151ToolReadinessReceipt, error) {
	var receipt codex0151ToolReadinessReceipt
	raw, err := os.ReadFile(codex01491TerminalRepoPath(codex0151C2PACaptureToolSuccessorPath))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("Codex CLI 0.151 C2PA 工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 C2PA 工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151C2PACaptureToolSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151C2PACaptureToolSuccessor(receipt codex0151ToolReadinessReceipt) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-c2pa-capture-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T15:49:59Z" ||
		receipt.BaseCommit != "ee04bf411c514bcb0fea6d5c66de976a6ac3e8ca" ||
		receipt.Scope != "codex-cli-0.151-c2pa-capture-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_c2pa_capture_tool_successor" {
		return errors.New("Codex CLI 0.151 C2PA 工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_tool_readiness_source_transition" ||
		receipt.Predecessor.Path != codex0151ToolReadinessTransitionPath ||
		receipt.Predecessor.SHA256 != "6571d18697e789da234476740b537f6301c918bd245a71b5573bed3765a49d69" {
		return errors.New("Codex CLI 0.151 C2PA 工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(codex01491TerminalRepoPath(receipt.Predecessor.Path))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 C2PA 工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 C2PA 工具后继 transition 验证集合非法")
	}
	if receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 C2PA 工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_01491_terminal_state_test.go":       "79bd57af20de63eb6b45cdda6509e8843ae5b9dd5d416465af05b57310af60d3",
		"backend/internal/service/codex_01491_terminal_state_test.go":              "8bcca0b49d4ccf90c0db38b54549864891a3f9272310b5428d49d0c26148b7aa",
		"tools/official_client_capture/build_scenario_facts.py":                    "411d22144b07ef26c1aa208452fe966692b6e3ef87fe500865f99bae4aaf3c3d",
		"tools/official_client_capture/codex_upgrade_scenario_receipt.schema.json": "046db28b8d86222b6613ff8692ee73e240fb91ea675fe4b3ee708ec5138410f2",
		"tools/official_client_capture/run_candidate_aux_capture.sh":               "3af73b725243de71109ab51910d8b5d4e919dd53112c7a42622761d191944fae",
		"tools/official_client_capture/run_official_relay_scenario.sh":             "f7fbe312381cc373332f0809ba23eeeecb4cbed6c63baaf33ac23333c1ed3e8c",
		"tools/official_client_capture/scenario_receipts.py":                       "b8e34ed888440dfde743ac3babf24ae9104fa129520b73abe17b24a3c2ff5e39",
		"tools/official_client_capture/tests/test_candidate_aux_capture.py":        "6cf6aeb2b6b68d2a5de9efdf1dcf5f5c2c05ffe6b410a31b3955394c444b9527",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                "2f29e29a06c082d36ece4c59b022ea206f81e4bf92d5f83c63e62069b908cf06",
		"tools/official_client_capture/tests/test_scenario_receipt.py":             "3ed76d36ec298f71e0de0f7303474a9d49419f39a7ffc2f9516ed52f0e03393d",
		"tools/official_client_capture/tests/test_upstream_byte_relay.py":          "3907ffe23126d1d1ebea9f206735cb416129aa68adc50ae82c080aaa3005f63c",
		"tools/official_client_capture/upstream_byte_relay.py":                     "b7912b0cdad7784b3a70d8a5f4a99265aa3d5f4e5b41ddba1e39acb1ea802fe9",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_c2pa_capture_tool_successor_test.go": {},
		"backend/internal/service/codex_0151_c2pa_capture_tool_successor_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-c2pa-capture-tool-successor/plan.json":   {},
		"tools/official_client_capture/codex_upgrade_rules_0_151_0.json":                 {},
		"tools/official_client_capture/codex_upgrade_scenarios_0_151_0.json":             {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 C2PA 工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(transition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!codex0151ModelPolicyToolSuccessorSupersedes(
				transition.Path,
				transition.ToSHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 C2PA 工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!receiptSHA256(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 C2PA 工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(codex01491TerminalRepoPath(addition.Path))
		currentDigest := upstreamMergeFrameworkDigest(current)
		if readErr != nil || (currentDigest != addition.SHA256 &&
			!codex0151ModelPolicyToolSuccessorSupersedes(
				addition.Path,
				addition.SHA256,
				currentDigest,
			)) {
			return errors.New("Codex CLI 0.151 C2PA 工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 C2PA 工具后继路径闭集非法")
	}
	return nil
}

// codex0151C2PACaptureToolSuccessorSupersedes 只承接 C2PA 工具后继的精确摘要边。
func codex0151C2PACaptureToolSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151C2PACaptureToolSuccessor()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest &&
			(transition.ToSHA256 == currentDigest ||
				codex0151ModelPolicyToolSuccessorSupersedes(
					path,
					transition.ToSHA256,
					currentDigest,
				)) {
			return true
		}
	}
	return codex0151ModelPolicyToolSuccessorSupersedes(path, priorDigest, currentDigest)
}

func TestCodex0151C2PACaptureToolSuccessorSourceTransitionIsFrozen(t *testing.T) {
	if _, err := loadCodex0151C2PACaptureToolSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151C2PACaptureToolSuccessorSourceTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151C2PACaptureToolSuccessor()
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
				mutated.Additions = append([]openAIReplayOOMRepairAddition(nil), mutated.Additions[1:]...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := receipt
			test.mutate(&mutated)
			if err := validateCodex0151C2PACaptureToolSuccessor(mutated); err == nil {
				t.Fatal("变异后的 C2PA 工具后继 transition 被错误接受")
			}
		})
	}
}
