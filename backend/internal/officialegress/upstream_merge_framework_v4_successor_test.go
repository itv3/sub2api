package officialegress

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

const upstreamMergeFrameworkV4SuccessorPath = "docs/egress/maintenance/upstream-v0.2.3-framework-v3-successor.json"

type upstreamMergeFrameworkV4Predecessor struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type upstreamMergeFrameworkV4SourceTransition struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	BaseCommit    string `json:"base_commit"`
	CurrentCommit string `json:"current_commit"`
}

type upstreamMergeFrameworkV4Receipt struct {
	SchemaVersion        string                                   `json:"schema_version"`
	IssuedAtUTC          string                                   `json:"issued_at_utc"`
	BaseCommit           string                                   `json:"base_commit"`
	TargetUpstreamTag    string                                   `json:"target_upstream_tag"`
	TargetUpstreamCommit string                                   `json:"target_upstream_commit"`
	Scope                string                                   `json:"scope"`
	Predecessor          upstreamMergeFrameworkV4Predecessor      `json:"predecessor"`
	SourceTransition     upstreamMergeFrameworkV4SourceTransition `json:"source_transition"`
	Transitions          []upstreamMergeFrameworkV3Transition     `json:"transitions"`
	Verification         []string                                 `json:"verification"`
	Safety               upstreamMergeFrameworkV3Safety           `json:"safety"`
	Result               string                                   `json:"result"`
	IdentitySHA256       string                                   `json:"identity_sha256"`
}

var (
	upstreamMergeFrameworkV4Once    sync.Once
	upstreamMergeFrameworkV4Cached  upstreamMergeFrameworkV4Receipt
	upstreamMergeFrameworkV4LoadErr error
)

func loadUpstreamMergeFrameworkV4Successor() (upstreamMergeFrameworkV4Receipt, error) {
	upstreamMergeFrameworkV4Once.Do(func() {
		upstreamMergeFrameworkV4Cached, upstreamMergeFrameworkV4LoadErr =
			readUpstreamMergeFrameworkV4Successor()
	})
	return upstreamMergeFrameworkV4Cached, upstreamMergeFrameworkV4LoadErr
}

func readUpstreamMergeFrameworkV4Successor() (upstreamMergeFrameworkV4Receipt, error) {
	var receipt upstreamMergeFrameworkV4Receipt
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(upstreamMergeFrameworkV4SuccessorPath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("上游合并框架 v0.2.3 successor 尾部存在额外 JSON")
	}
	var identityDocument map[string]any
	if err := json.Unmarshal(raw, &identityDocument); err != nil {
		return receipt, err
	}
	delete(identityDocument, "identity_sha256")
	canonical, err := json.Marshal(identityDocument)
	if err != nil || upstreamMergeFrameworkV3Digest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("上游合并框架 v0.2.3 successor 自摘要不一致")
	}
	if err := validateUpstreamMergeFrameworkV4Successor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateUpstreamMergeFrameworkV4Successor(receipt upstreamMergeFrameworkV4Receipt) error {
	if receipt.SchemaVersion != "official-egress-upstream-v0.2.3-framework-v3-successor/v1" ||
		receipt.IssuedAtUTC != "2026-09-09T10:30:00Z" ||
		receipt.BaseCommit != "681909c2e1bddcbf2a3700c7713e03647507fe26" ||
		receipt.TargetUpstreamTag != "v0.2.3" ||
		receipt.TargetUpstreamCommit != "8fa67d477d6651a744754392a8982ea589c26ae6" ||
		receipt.Scope != "upstream-v0.2.3-framework-v3-successor" ||
		receipt.Result != "passed_local_evidence_successor" ||
		len(receipt.Transitions) != 6 ||
		!slices.Equal(receipt.Verification, []string{
			"go test ./internal/service -count=1",
			"go test ./internal/officialegress/... -count=1",
			"make test-upstream-merge-tools",
			"make check-egress-spec",
		}) || receipt.Safety.LiveAccountUsed || receipt.Safety.ProductionConfigChanged ||
		receipt.Safety.OfficialEgressProfileChanged || receipt.Safety.WireOrPersonaSelectionChanged {
		return errors.New("上游合并框架 v0.2.3 successor 顶层事实非法")
	}
	if receipt.Predecessor.Path != upstreamMergeFrameworkV3SuccessorPath ||
		receipt.Predecessor.SHA256 != "ce48d7b4d6c0adcca18948a55683dcd177dca9be854d588d38da6a2bdde43403" {
		return errors.New("上游合并框架 v0.2.3 successor 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkV3Digest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("上游合并框架 v0.2.3 successor 前序摘要不一致")
	}
	if receipt.SourceTransition.Path != upstreamV023SourceTransitionPath ||
		!receiptSHA256(receipt.SourceTransition.SHA256) ||
		receipt.SourceTransition.BaseCommit != receipt.BaseCommit ||
		!upstreamV023GitObject(receipt.SourceTransition.CurrentCommit) {
		return errors.New("上游合并框架 v0.2.3 successor 通用 transition 绑定非法")
	}
	sourceRaw, err := os.ReadFile(filepath.Join(
		"../../..", filepath.FromSlash(receipt.SourceTransition.Path),
	))
	if err != nil || upstreamMergeFrameworkV3Digest(sourceRaw) != receipt.SourceTransition.SHA256 {
		return errors.New("上游合并框架 v0.2.3 successor 通用 transition 摘要不一致")
	}
	sourceReceipt, err := readUpstreamV023SourceTransition()
	if err != nil || sourceReceipt.BaseCommit != receipt.SourceTransition.BaseCommit ||
		sourceReceipt.CurrentCommit != receipt.SourceTransition.CurrentCommit {
		return errors.New("上游合并框架 v0.2.3 successor 通用 transition 提交绑定不一致")
	}
	expectedFrom := map[string]string{
		"backend/internal/handler/openai_gateway_handler.go":              "7052b4455af267b889b9eb4deeb97d856697f3db61e97e6a2a5a636a89221168",
		"backend/internal/service/gateway_context_management_test.go":     "a15304642a243ef16f2d91870c6a9d9d1b089481d62c5c697986d82ac9706f41",
		"backend/internal/service/gateway_forward_as_chat_completions.go": "ce75d3720da98bde94c17ccba387b5b0ca9c4c8a25a492e1afc5248f2a6b5fc7",
		"backend/internal/service/gateway_forward_as_responses.go":        "2657c0f62fc269ddb604738ca17d43b0dbe6f38828747b8351f1a840d03473ac",
		"backend/internal/service/official_egress_openai_ws_test.go":      "4fac8d6e1adb48b20f914690ea12377c3704d9db61cea368d942b13f6d28906f",
		"backend/internal/service/openai_ws_pool.go":                      "fa1d3b3f437ee3b387117982bee04b9c91762a925f427c5230cc28ba5b8b947d",
	}
	expectedSources := []string{
		"docs/egress/maintenance/upstream-merge-framework-v3-source-transition.json",
		"docs/egress/maintenance/upstream-v0.2.3-egress-merge-ledger.json",
	}
	paths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		from, ok := expectedFrom[transition.Path]
		if !ok || !slices.Equal(transition.PredecessorSHA256s, []string{from}) ||
			!receiptSHA256(transition.ToSHA256) || transition.ToSHA256 == from ||
			!slices.Equal(transition.SourceReceipts, expectedSources) ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("上游合并框架 v0.2.3 successor 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		if readErr != nil || upstreamMergeFrameworkV3Digest(current) != transition.ToSHA256 {
			return errors.New("上游合并框架 v0.2.3 successor 当前摘要不一致：" + transition.Path)
		}
		paths = append(paths, transition.Path)
	}
	if !slices.IsSorted(paths) || len(paths) != len(slices.Compact(append([]string(nil), paths...))) {
		return errors.New("上游合并框架 v0.2.3 successor 路径未严格排序")
	}
	return nil
}

func upstreamMergeFrameworkV4SuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	if !receiptSHA256(priorDigest) || !receiptSHA256(currentDigest) || priorDigest == currentDigest {
		return false
	}
	receipt, err := loadUpstreamMergeFrameworkV4Successor()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.ToSHA256 == currentDigest &&
			slices.Contains(transition.PredecessorSHA256s, priorDigest) {
			return true
		}
	}
	return false
}

func TestUpstreamMergeFrameworkV4SuccessorIsFrozen(t *testing.T) {
	if _, err := loadUpstreamMergeFrameworkV4Successor(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamMergeFrameworkV4SuccessorRejectsMutation(t *testing.T) {
	receipt, err := loadUpstreamMergeFrameworkV4Successor()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]upstreamMergeFrameworkV3Transition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateUpstreamMergeFrameworkV4Successor(mutated); err == nil {
		t.Fatal("变异后的上游合并框架 v0.2.3 successor 被错误接受")
	}
}
