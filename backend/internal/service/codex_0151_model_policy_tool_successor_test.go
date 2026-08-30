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

const codex0151ModelPolicyToolSuccessorServicePath = "docs/egress/maintenance/codex-cli-0151-model-policy-tool-successor-source-transition.json"

var (
	codex0151ModelPolicyToolSuccessorServiceOnce   sync.Once
	codex0151ModelPolicyToolSuccessorServiceCached codex0151ToolReadinessReceiptService
	codex0151ModelPolicyToolSuccessorServiceErr    error
)

func loadCodex0151ModelPolicyToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	codex0151ModelPolicyToolSuccessorServiceOnce.Do(func() {
		codex0151ModelPolicyToolSuccessorServiceCached, codex0151ModelPolicyToolSuccessorServiceErr =
			readCodex0151ModelPolicyToolSuccessorService()
	})
	return codex0151ModelPolicyToolSuccessorServiceCached, codex0151ModelPolicyToolSuccessorServiceErr
}

func readCodex0151ModelPolicyToolSuccessorService() (codex0151ToolReadinessReceiptService, error) {
	var receipt codex0151ToolReadinessReceiptService
	raw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(codex0151ModelPolicyToolSuccessorServicePath),
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
		return receipt, errors.New("Codex CLI 0.151 模型政策工具后继 transition 尾部存在额外 JSON")
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
		return receipt, errors.New("Codex CLI 0.151 模型政策工具后继 transition 自摘要不一致")
	}
	if err := validateCodex0151ModelPolicyToolSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateCodex0151ModelPolicyToolSuccessorService(receipt codex0151ToolReadinessReceiptService) error {
	if receipt.SchemaVersion != "sub2apiplus-codex-cli-0151-model-policy-tool-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-08-30T16:24:00Z" ||
		receipt.BaseCommit != "0c8cac7189746436bc11aadb8eae6e70d31675eb" ||
		receipt.Scope != "codex-cli-0.151-model-policy-tool-successor" ||
		receipt.Result != "passed_codex_cli_0151_model_policy_tool_successor" {
		return errors.New("Codex CLI 0.151 模型政策工具后继 transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_c2pa_capture_tool_successor_source_transition" ||
		receipt.Predecessor.Path != codex0151C2PACaptureToolSuccessorServicePath ||
		receipt.Predecessor.SHA256 != "b53217ae5decf79064337e7111b153f75f27b0b5d533ccb6931a7422f3a74dde" {
		return errors.New("Codex CLI 0.151 模型政策工具后继 transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join(
		"../../..",
		filepath.FromSlash(receipt.Predecessor.Path),
	))
	if err != nil || upstreamMergeFrameworkServiceDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("Codex CLI 0.151 模型政策工具后继 transition 前序摘要不一致")
	}
	expectedVerification := []string{
		"python3 -m unittest discover -s tools/official_client_capture/tests -p 'test_*.py'",
		"go test ./internal/officialegress ./internal/service -run 'TestCodex(01491Terminal|0151)' -count=1",
		"make check-egress-spec",
	}
	if !slices.Equal(receipt.Verification, expectedVerification) {
		return errors.New("Codex CLI 0.151 模型政策工具后继 transition 验证集合非法")
	}
	if !receipt.Safety.LiveAccountUsed || receipt.Safety.OnlineAcceptancePerformed ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.OfficialEgressProfileChanged {
		return errors.New("Codex CLI 0.151 模型政策工具后继 transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/internal/officialegress/codex_0151_c2pa_capture_tool_successor_test.go": "e1d155184fd9bffb5b98660d7469f3e045675fef564f3167c0cf3f0385f7e1ad",
		"backend/internal/service/codex_0151_c2pa_capture_tool_successor_test.go":        "0b1842a1ba57a91b16523484dd25d377aeb4e25844c594eccfd37de377934d7a",
		"tools/official_client_capture/capturelib/model.py":                              "3eb5ba89ab9f7047a02b8201f58c6e29facf1ef57097c2be1d67e373425d51cd",
		"tools/official_client_capture/codex_upgrade.py":                                 "da84e04034b0583bd48ae3f5dafbbb29e3f2cc5f8d12b922a7a7eeec5cc1ad67",
		"tools/official_client_capture/tests/test_codex_upgrade.py":                      "c15862fc4d709bc2fc732abc70346bf3674ef5765ca2feaa686e9ec336ff3b24",
		"tools/official_client_capture/tests/test_main_track_models.py":                  "1c01dd26e947c8a05551de25a425be6c75e3d22aa2c81d423be53291b86b4c55",
	}
	expectedAdditions := map[string]struct{}{
		"backend/internal/officialegress/codex_0151_model_policy_tool_successor_test.go": {},
		"backend/internal/service/codex_0151_model_policy_tool_successor_test.go":        {},
		"docs/egress/maintenance/codex-cli-0151-model-policy-tool-successor/plan.json":   {},
	}
	transitionPaths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
			transition.FromSHA256 == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" {
			return errors.New("Codex CLI 0.151 模型政策工具后继 transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(current) != transition.ToSHA256 {
			return errors.New("Codex CLI 0.151 模型政策工具后继 transition 当前摘要不一致：" + transition.Path)
		}
		transitionPaths = append(transitionPaths, transition.Path)
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok ||
			!validOpenAIReplayOOMRepairServiceSHA(addition.SHA256) || strings.TrimSpace(addition.Reason) == "" {
			return errors.New("Codex CLI 0.151 模型政策工具后继 addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(current) != addition.SHA256 {
			return errors.New("Codex CLI 0.151 模型政策工具后继 addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(transitionPaths) ||
		len(transitionPaths) != len(slices.Compact(append([]string(nil), transitionPaths...))) ||
		!slices.IsSorted(additionPaths) ||
		len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("Codex CLI 0.151 模型政策工具后继路径闭集非法")
	}
	return nil
}

// codex0151ModelPolicyToolSuccessorSupersedesService 只承接模型政策工具后继的精确摘要边。
func codex0151ModelPolicyToolSuccessorSupersedesService(path, priorDigest, currentDigest string) bool {
	receipt, err := loadCodex0151ModelPolicyToolSuccessorService()
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

func TestCodex0151ModelPolicyToolSuccessorSourceTransitionServiceIsFrozen(t *testing.T) {
	if _, err := loadCodex0151ModelPolicyToolSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestCodex0151ModelPolicyToolSuccessorSourceTransitionServiceRejectsMutation(t *testing.T) {
	receipt, err := loadCodex0151ModelPolicyToolSuccessorService()
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
			name: "安全边界漂移",
			mutate: func(mutated *codex0151ToolReadinessReceiptService) {
				mutated.Safety.LiveAccountUsed = false
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
			if err := validateCodex0151ModelPolicyToolSuccessorService(mutated); err == nil {
				t.Fatal("变异后的模型政策工具后继 transition 被错误接受")
			}
		})
	}
}
