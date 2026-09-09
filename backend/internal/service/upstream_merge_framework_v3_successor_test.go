package service

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

// service 包独立重放 v3 successor，避免 officialegress 包通过而 service 包漏检。
const upstreamMergeFrameworkV3SuccessorServicePath = "docs/egress/maintenance/upstream-merge-framework-v3-source-transition.json"

type upstreamMergeFrameworkV3ServiceTransition struct {
	Path               string   `json:"path"`
	PredecessorSHA256s []string `json:"predecessor_sha256s"`
	ToSHA256           string   `json:"to_sha256"`
	SourceReceipts     []string `json:"source_receipts"`
	Reason             string   `json:"reason"`
}

type upstreamMergeFrameworkV3ServiceSafety struct {
	LiveAccountUsed               bool `json:"live_account_used"`
	ProductionConfigChanged       bool `json:"production_config_changed"`
	OfficialEgressProfileChanged  bool `json:"official_egress_profile_changed"`
	WireOrPersonaSelectionChanged bool `json:"wire_or_persona_selection_changed"`
}

type upstreamMergeFrameworkV3ServiceReceipt struct {
	SchemaVersion     string                                      `json:"schema_version"`
	IssuedAtUTC       string                                      `json:"issued_at_utc"`
	BaseCommit        string                                      `json:"base_commit"`
	Scope             string                                      `json:"scope"`
	Purpose           string                                      `json:"purpose"`
	Transitions       []upstreamMergeFrameworkV3ServiceTransition `json:"transitions"`
	AllowedWireDeltas []string                                    `json:"allowed_wire_deltas"`
	Verification      []string                                    `json:"verification"`
	Safety            upstreamMergeFrameworkV3ServiceSafety       `json:"safety"`
	Result            string                                      `json:"result"`
	IdentitySHA256    string                                      `json:"identity_sha256"`
}

var (
	upstreamMergeFrameworkV3ServiceOnce    sync.Once
	upstreamMergeFrameworkV3ServiceCached  upstreamMergeFrameworkV3ServiceReceipt
	upstreamMergeFrameworkV3ServiceLoadErr error
)

func upstreamMergeFrameworkV3ServiceDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func loadUpstreamMergeFrameworkV3SuccessorService() (
	upstreamMergeFrameworkV3ServiceReceipt,
	error,
) {
	upstreamMergeFrameworkV3ServiceOnce.Do(func() {
		upstreamMergeFrameworkV3ServiceCached,
			upstreamMergeFrameworkV3ServiceLoadErr =
			readUpstreamMergeFrameworkV3SuccessorService()
	})
	return upstreamMergeFrameworkV3ServiceCached,
		upstreamMergeFrameworkV3ServiceLoadErr
}

func readUpstreamMergeFrameworkV3SuccessorService() (
	upstreamMergeFrameworkV3ServiceReceipt,
	error,
) {
	var receipt upstreamMergeFrameworkV3ServiceReceipt
	raw, err := os.ReadFile(filepath.Join(
		"../../..", filepath.FromSlash(upstreamMergeFrameworkV3SuccessorServicePath),
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
	if err != nil || upstreamMergeFrameworkV3ServiceDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("上游合并框架 v3 successor 自摘要不一致")
	}
	if err := validateUpstreamMergeFrameworkV3SuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateUpstreamMergeFrameworkV3SuccessorService(
	receipt upstreamMergeFrameworkV3ServiceReceipt,
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
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) ||
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
			if !validOpenAIReplayOOMRepairServiceSHA(predecessor) ||
				predecessor == transition.ToSHA256 {
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
		currentDigest := upstreamMergeFrameworkV3ServiceDigest(current)
		if readErr != nil || (currentDigest != transition.ToSHA256 &&
			!upstreamMergeFrameworkV4SuccessorSupersedesService(
				transition.Path, transition.ToSHA256, currentDigest,
			) && !upstreamV023SourceTransitionDirectSupersedesService(
			transition.Path, transition.ToSHA256, currentDigest,
		) && !auditedSourceSuccessorReachesService(
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

// service 包的摘要门禁只接受 v3 收据登记的精确边。
func upstreamMergeFrameworkV3SuccessorSupersedesService(
	path string,
	priorDigest string,
	currentDigest string,
) bool {
	if !validOpenAIReplayOOMRepairServiceSHA(priorDigest) ||
		!validOpenAIReplayOOMRepairServiceSHA(currentDigest) ||
		priorDigest == currentDigest {
		return false
	}
	receipt, err := loadUpstreamMergeFrameworkV3SuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && slices.Contains(transition.PredecessorSHA256s, priorDigest) {
			if transition.ToSHA256 == currentDigest ||
				upstreamMergeFrameworkV4SuccessorSupersedesService(
					path, transition.ToSHA256, currentDigest,
				) || upstreamV023SourceTransitionDirectSupersedesService(
				path, transition.ToSHA256, currentDigest,
			) {
				return true
			}
		}
	}
	return false
}

func TestUpstreamMergeFrameworkV3SuccessorServiceIsFrozen(t *testing.T) {
	if _, err := loadUpstreamMergeFrameworkV3SuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamMergeFrameworkV3SuccessorServiceRejectsMutation(t *testing.T) {
	receipt, err := loadUpstreamMergeFrameworkV3SuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append(
		[]upstreamMergeFrameworkV3ServiceTransition(nil), receipt.Transitions...,
	)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateUpstreamMergeFrameworkV3SuccessorService(mutated); err == nil {
		t.Fatal("变异后的上游合并框架 v3 successor 被错误接受")
	}
}
