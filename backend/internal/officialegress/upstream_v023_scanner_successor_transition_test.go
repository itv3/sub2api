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

const upstreamV023ScannerSuccessorTransitionPath = "docs/egress/maintenance/upstream-v0.2.3-scanner-successor-source-transition.json"

type upstreamV023ScannerSuccessorPredecessor struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type upstreamV023ScannerSuccessorTransition struct {
	Path       string `json:"path"`
	FromSHA256 string `json:"from_sha256"`
	ToSHA256   string `json:"to_sha256"`
	Reason     string `json:"reason"`
}

type upstreamV023ScannerSuccessorAddition struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Reason string `json:"reason"`
}

type upstreamV023ScannerSuccessorSafety struct {
	ScannerAlgorithmChanged   bool `json:"scanner_algorithm_changed"`
	BootstrapInventoryChanged bool `json:"bootstrap_inventory_changed"`
	LiveAccountUsed           bool `json:"live_account_used"`
	DeploymentPerformed       bool `json:"deployment_performed"`
}

type upstreamV023ScannerSuccessorReceipt struct {
	SchemaVersion        string                                   `json:"schema_version"`
	IssuedAtUTC          string                                   `json:"issued_at_utc"`
	BaseCommit           string                                   `json:"base_commit"`
	Scope                string                                   `json:"scope"`
	TargetUpstreamTag    string                                   `json:"target_upstream_tag"`
	TargetUpstreamCommit string                                   `json:"target_upstream_commit"`
	Predecessor          upstreamV023ScannerSuccessorPredecessor  `json:"predecessor"`
	Transitions          []upstreamV023ScannerSuccessorTransition `json:"transitions"`
	Additions            []upstreamV023ScannerSuccessorAddition   `json:"additions"`
	Verification         []string                                 `json:"verification"`
	Safety               upstreamV023ScannerSuccessorSafety       `json:"safety"`
	Result               string                                   `json:"result"`
	IdentitySHA256       string                                   `json:"identity_sha256"`
}

var (
	upstreamV023ScannerSuccessorOnce    sync.Once
	upstreamV023ScannerSuccessorCached  upstreamV023ScannerSuccessorReceipt
	upstreamV023ScannerSuccessorLoadErr error
)

func loadUpstreamV023ScannerSuccessorTransition() (upstreamV023ScannerSuccessorReceipt, error) {
	upstreamV023ScannerSuccessorOnce.Do(func() {
		upstreamV023ScannerSuccessorCached,
			upstreamV023ScannerSuccessorLoadErr = readUpstreamV023ScannerSuccessorTransition()
	})
	return upstreamV023ScannerSuccessorCached, upstreamV023ScannerSuccessorLoadErr
}

func readUpstreamV023ScannerSuccessorTransition() (upstreamV023ScannerSuccessorReceipt, error) {
	var receipt upstreamV023ScannerSuccessorReceipt
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(upstreamV023ScannerSuccessorTransitionPath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("上游 v0.2.3 scanner successor transition 尾部存在额外 JSON")
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
		return receipt, errors.New("上游 v0.2.3 scanner successor transition 自摘要不一致")
	}
	if err := validateUpstreamV023ScannerSuccessorTransition(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateUpstreamV023ScannerSuccessorTransition(receipt upstreamV023ScannerSuccessorReceipt) error {
	if receipt.SchemaVersion != "official-egress-upstream-v0.2.3-scanner-successor-source-transition/v1" ||
		receipt.IssuedAtUTC != "2026-09-09T00:00:00Z" ||
		receipt.BaseCommit != "5dc9788bddef63cb9ef40dba67d8b0888d4d0f251" ||
		receipt.Scope != "upstream-v0.2.3-scanner-classification-successor" ||
		receipt.TargetUpstreamTag != "v0.2.3" ||
		receipt.TargetUpstreamCommit != "8fa67d477d6651a744754392a8982ea589c26ae6" ||
		receipt.Result != "passed_local_scanner_successor" {
		return errors.New("上游 v0.2.3 scanner successor transition 顶层事实非法")
	}
	if receipt.Predecessor.Kind != "codex_cli_0151_worktree_successor" ||
		receipt.Predecessor.Path != "docs/egress/maintenance/codex-cli-0151-worktree-successor.json" ||
		receipt.Predecessor.SHA256 != "49ca837b912bfbe33c2631a6bc0b6bbfe6dba1d3ad37efbc835bb45d043045be" {
		return errors.New("上游 v0.2.3 scanner successor transition 前序非法")
	}
	predecessorRaw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(receipt.Predecessor.Path)))
	if err != nil || upstreamMergeFrameworkDigest(predecessorRaw) != receipt.Predecessor.SHA256 {
		return errors.New("上游 v0.2.3 scanner successor transition 前序摘要不一致")
	}
	if !slices.Equal(receipt.Verification, []string{
		"go test ./cmd/egressscan -count=1",
		"go test ./internal/officialegress ./internal/service -run 'TestUpstreamV023ScannerSuccessor|TestUpstreamV0180' -count=1",
		"EGRESS_SEAL_BASE_REF=5dc9788bddef63cb9ef40dba67d8b0888d4d0f251 make check-egress-spec-ci",
	}) {
		return errors.New("上游 v0.2.3 scanner successor transition 验证集合非法")
	}
	if !receipt.Safety.ScannerAlgorithmChanged || !receipt.Safety.BootstrapInventoryChanged ||
		receipt.Safety.LiveAccountUsed || receipt.Safety.DeploymentPerformed {
		return errors.New("上游 v0.2.3 scanner successor transition 安全边界非法")
	}
	expectedFrom := map[string]string{
		"backend/cmd/egressscan/classify.go":                                          "1ed55101182ad64efaed965794a982ac4dad1a62fcde58260f02969d6d830378",
		"backend/cmd/egressscan/lifecycle_test.go":                                    "f0f4b3e03341e2b949b91a5722f8b0951ddd055906a63f8fbc015f6c2e02532b",
		"backend/internal/officialegress/source_transition_digest_acceptance_test.go": "1c2f952bd7ed834b0ffc49826a9ac29e399c945d4eace07dc59d76c05327ce5d",
		"backend/internal/service/source_transition_digest_acceptance_test.go":        "e0d8c11109d5ca90fae5161224cec5c5204c0821e3150547ae054b41dad550dd",
		"docs/egress/maintenance/bootstrap-inventory-lock.json":                       "d94bfe584b1cfb61bb852c7c6de9dbc3298084c0a95e329c960b0ee12fc0f0a2",
	}
	paths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if expectedFrom[transition.Path] != transition.FromSHA256 ||
			!receiptSHA256(transition.ToSHA256) || transition.FromSHA256 == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" {
			return errors.New("上游 v0.2.3 scanner successor transition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != transition.ToSHA256 {
			return errors.New("上游 v0.2.3 scanner successor transition 当前摘要不一致：" + transition.Path)
		}
		paths = append(paths, transition.Path)
	}
	expectedAdditions := map[string]struct{}{
		"backend/cmd/egressscan/classify_upstream_v023_test.go":                              {},
		"backend/internal/officialegress/upstream_v023_scanner_successor_transition_test.go": {},
		"backend/internal/service/upstream_v023_scanner_successor_transition_test.go":        {},
	}
	additionPaths := make([]string, 0, len(receipt.Additions))
	for _, addition := range receipt.Additions {
		if _, ok := expectedAdditions[addition.Path]; !ok || !receiptSHA256(addition.SHA256) ||
			strings.TrimSpace(addition.Reason) == "" {
			return errors.New("上游 v0.2.3 scanner successor addition 条目非法")
		}
		current, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(addition.Path)))
		if readErr != nil || upstreamMergeFrameworkDigest(current) != addition.SHA256 {
			return errors.New("上游 v0.2.3 scanner successor addition 当前摘要不一致：" + addition.Path)
		}
		additionPaths = append(additionPaths, addition.Path)
	}
	if len(receipt.Transitions) != len(expectedFrom) || len(receipt.Additions) != len(expectedAdditions) ||
		!slices.IsSorted(paths) || len(paths) != len(slices.Compact(append([]string(nil), paths...))) ||
		!slices.IsSorted(additionPaths) || len(additionPaths) != len(slices.Compact(append([]string(nil), additionPaths...))) {
		return errors.New("上游 v0.2.3 scanner successor 路径闭集非法")
	}
	return nil
}

func upstreamV023ScannerSuccessorTransitionSupersedes(path, priorDigest, currentDigest string) bool {
	receipt, err := loadUpstreamV023ScannerSuccessorTransition()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.FromSHA256 == priorDigest && transition.ToSHA256 == currentDigest {
			return true
		}
	}
	for _, addition := range receipt.Additions {
		if addition.Path == path && addition.SHA256 == priorDigest && addition.SHA256 == currentDigest {
			return true
		}
	}
	return false
}

func TestUpstreamV023ScannerSuccessorTransitionIsFrozen(t *testing.T) {
	if _, err := loadUpstreamV023ScannerSuccessorTransition(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamV023ScannerSuccessorTransitionRejectsMutation(t *testing.T) {
	receipt, err := loadUpstreamV023ScannerSuccessorTransition()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]upstreamV023ScannerSuccessorTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateUpstreamV023ScannerSuccessorTransition(mutated); err == nil {
		t.Fatal("变异后的上游 v0.2.3 scanner successor transition 被错误接受")
	}
}
