package officialegress

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// upstreamMergeFrameworkV3SuccessorPath 是本次合并框架修复产生的追加收据。
// v2 及更早收据保持只读；本收据只登记本地历史证据路径的精确后继摘要。
const upstreamMergeFrameworkV3SuccessorPath = "docs/egress/maintenance/upstream-merge-framework-v3-source-transition.json"

type upstreamMergeFrameworkV3Transition struct {
	Path               string   `json:"path"`
	PredecessorSHA256s []string `json:"predecessor_sha256s"`
	ToSHA256           string   `json:"to_sha256"`
	SourceReceipts     []string `json:"source_receipts"`
	Reason             string   `json:"reason"`
}

type upstreamMergeFrameworkV3Safety struct {
	LiveAccountUsed               bool `json:"live_account_used"`
	ProductionConfigChanged       bool `json:"production_config_changed"`
	OfficialEgressProfileChanged  bool `json:"official_egress_profile_changed"`
	WireOrPersonaSelectionChanged bool `json:"wire_or_persona_selection_changed"`
}

type upstreamMergeFrameworkV3Receipt struct {
	SchemaVersion     string                               `json:"schema_version"`
	IssuedAtUTC       string                               `json:"issued_at_utc"`
	BaseCommit        string                               `json:"base_commit"`
	Scope             string                               `json:"scope"`
	Purpose           string                               `json:"purpose"`
	Transitions       []upstreamMergeFrameworkV3Transition `json:"transitions"`
	AllowedWireDeltas []string                             `json:"allowed_wire_deltas"`
	Verification      []string                             `json:"verification"`
	Safety            upstreamMergeFrameworkV3Safety       `json:"safety"`
	Result            string                               `json:"result"`
	IdentitySHA256    string                               `json:"identity_sha256"`
}

var (
	upstreamMergeFrameworkV3Once    sync.Once
	upstreamMergeFrameworkV3Cached  upstreamMergeFrameworkV3Receipt
	upstreamMergeFrameworkV3LoadErr error
)

func upstreamMergeFrameworkV3Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func loadUpstreamMergeFrameworkV3Successor() (
	upstreamMergeFrameworkV3Receipt,
	error,
) {
	upstreamMergeFrameworkV3Once.Do(func() {
		upstreamMergeFrameworkV3Cached, upstreamMergeFrameworkV3LoadErr =
			readUpstreamMergeFrameworkV3Successor()
	})
	return upstreamMergeFrameworkV3Cached, upstreamMergeFrameworkV3LoadErr
}

func readUpstreamMergeFrameworkV3Successor() (
	upstreamMergeFrameworkV3Receipt,
	error,
) {
	var receipt upstreamMergeFrameworkV3Receipt
	raw, err := os.ReadFile(filepath.Join(
		"../../..", filepath.FromSlash(upstreamMergeFrameworkV3SuccessorPath),
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
		return receipt, errors.New("上游合并框架 v3 successor 尾部存在额外 JSON")
	}
	var identityDocument map[string]any
	if err := json.Unmarshal(raw, &identityDocument); err != nil {
		return receipt, err
	}
	delete(identityDocument, "identity_sha256")
	canonical, err := json.Marshal(identityDocument)
	if err != nil || upstreamMergeFrameworkV3Digest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("上游合并框架 v3 successor 自摘要不一致")
	}
	if err := validateUpstreamMergeFrameworkV3Successor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateUpstreamMergeFrameworkV3Successor(
	receipt upstreamMergeFrameworkV3Receipt,
) error {
	if receipt.SchemaVersion !=
		"official-egress-upstream-merge-framework-v3-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-09-09T06:00:00Z" ||
		receipt.BaseCommit != "236eb3d82f347effc4856d45940e7f9c071b7e0b" ||
		receipt.Scope != "upstream-merge-framework-historical-successor" ||
		receipt.Purpose != "historical_evidence_successor" ||
		receipt.Result != "passed_local_evidence_successor" ||
		len(receipt.Transitions) != 52 || len(receipt.AllowedWireDeltas) != 0 ||
		!slices.Equal(receipt.Verification, []string{
			"go test ./internal/service -count=1",
			"go test ./internal/officialegress/... -count=1",
			"make test-upstream-merge-tools",
			"make check-egress-spec",
		}) || receipt.Safety.LiveAccountUsed ||
		receipt.Safety.ProductionConfigChanged ||
		receipt.Safety.OfficialEgressProfileChanged ||
		receipt.Safety.WireOrPersonaSelectionChanged {
		return errors.New("上游合并框架 v3 successor 顶层事实非法")
	}
	paths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if strings.TrimSpace(transition.Path) == "" ||
			filepath.IsAbs(filepath.FromSlash(transition.Path)) ||
			strings.HasPrefix(filepath.ToSlash(transition.Path), "../") ||
			strings.HasPrefix(filepath.ToSlash(transition.Path), "/") ||
			!receiptSHA256(transition.ToSHA256) ||
			len(transition.PredecessorSHA256s) == 0 ||
			!slices.IsSorted(transition.PredecessorSHA256s) ||
			len(transition.PredecessorSHA256s) != len(slices.Compact(
				append([]string(nil), transition.PredecessorSHA256s...),
			)) || strings.TrimSpace(transition.Reason) == "" ||
			len(transition.SourceReceipts) == 0 ||
			!slices.IsSorted(transition.SourceReceipts) ||
			len(transition.SourceReceipts) != len(slices.Compact(
				append([]string(nil), transition.SourceReceipts...),
			)) {
			return errors.New("上游合并框架 v3 successor 条目非法")
		}
		for _, predecessor := range transition.PredecessorSHA256s {
			if !receiptSHA256(predecessor) || predecessor == transition.ToSHA256 {
				return errors.New("上游合并框架 v3 successor 前序摘要非法")
			}
		}
		for _, sourceReceipt := range transition.SourceReceipts {
			if filepath.IsAbs(filepath.FromSlash(sourceReceipt)) ||
				strings.HasPrefix(filepath.ToSlash(sourceReceipt), "../") ||
				strings.HasPrefix(filepath.ToSlash(sourceReceipt), "/") {
				return errors.New("上游合并框架 v3 successor 来源收据路径非法")
			}
			if _, err := os.Stat(filepath.Join(
				"../../..", filepath.FromSlash(sourceReceipt),
			)); err != nil {
				return errors.New("上游合并框架 v3 successor 来源收据不存在：" + sourceReceipt)
			}
		}
		current, readErr := os.ReadFile(filepath.Join(
			"../../..", filepath.FromSlash(transition.Path),
		))
		currentDigest := upstreamMergeFrameworkV3Digest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!upstreamMergeFrameworkV4SuccessorSupersedes(
				transition.Path, transition.ToSHA256, currentDigest,
			) && !upstreamV023SourceTransitionDirectSupersedes(
			transition.Path, transition.ToSHA256, currentDigest,
		) && !auditedSourceSuccessorReaches(
			transition.Path, transition.ToSHA256, currentDigest,
		)) {
			return errors.New("上游合并框架 v3 successor 当前摘要不一致：" + transition.Path)
		}
		paths = append(paths, transition.Path)
	}
	if !slices.IsSorted(paths) ||
		len(paths) != len(slices.Compact(append([]string(nil), paths...))) {
		return errors.New("上游合并框架 v3 successor 路径未严格排序")
	}
	return nil
}

// upstreamMergeFrameworkV3SuccessorSupersedes 只承认收据登记的精确
// path／前序摘要／当前摘要三元组，绝不把任意工作树修改视为合法。
func upstreamMergeFrameworkV3SuccessorSupersedes(
	path string,
	priorDigest string,
	currentDigest string,
) bool {
	if !receiptSHA256(priorDigest) || !receiptSHA256(currentDigest) ||
		priorDigest == currentDigest {
		return false
	}
	// 先走非递归的精确 successor 闭包；不能在另一个收据的 sync.Once
	// 初始化期间回调该收据 loader，否则会再次形成递归等待。
	if auditedSourceSuccessorReaches(path, priorDigest, currentDigest) {
		return true
	}
	receipt, err := loadUpstreamMergeFrameworkV3Successor()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && slices.Contains(transition.PredecessorSHA256s, priorDigest) {
			if transition.ToSHA256 == currentDigest ||
				upstreamMergeFrameworkV4SuccessorSupersedes(
					path, transition.ToSHA256, currentDigest,
				) || upstreamV023SourceTransitionDirectSupersedes(
				path, transition.ToSHA256, currentDigest,
			) {
				return true
			}
		}
	}
	return false
}

func TestUpstreamMergeFrameworkV3SuccessorIsFrozen(t *testing.T) {
	if _, err := loadUpstreamMergeFrameworkV3Successor(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamMergeFrameworkV3SuccessorRejectsMutation(t *testing.T) {
	receipt, err := loadUpstreamMergeFrameworkV3Successor()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append(
		[]upstreamMergeFrameworkV3Transition(nil), receipt.Transitions...,
	)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateUpstreamMergeFrameworkV3Successor(mutated); err == nil {
		t.Fatal("变异后的上游合并框架 v3 successor 被错误接受")
	}
}
