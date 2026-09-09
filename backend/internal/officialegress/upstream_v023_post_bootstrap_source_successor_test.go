package officialegress

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

const upstreamV023PostBootstrapSourceSuccessorPath = "docs/egress/maintenance/upstream-v0.2.3-post-bootstrap-source-successor.json"

type upstreamV023PostBootstrapSourceSuccessorTransition struct {
	Path               string   `json:"path"`
	PredecessorSHA256s []string `json:"predecessor_sha256s"`
	ToSHA256           string   `json:"to_sha256"`
	SourceReceipts     []string `json:"source_receipts"`
	Reason             string   `json:"reason"`
}

type upstreamV023PostBootstrapSourceSuccessorSafety struct {
	LiveAccountUsed               bool `json:"live_account_used"`
	OfficialEgressProfileChanged  bool `json:"official_egress_profile_changed"`
	ProductionConfigChanged       bool `json:"production_config_changed"`
	WireOrPersonaSelectionChanged bool `json:"wire_or_persona_selection_changed"`
	DeploymentPerformed           bool `json:"deployment_performed"`
}

type upstreamV023PostBootstrapSourceSuccessorReceipt struct {
	SchemaVersion  string                                               `json:"schema_version"`
	IssuedAtUTC    string                                               `json:"issued_at_utc"`
	BaseCommit     string                                               `json:"base_commit"`
	CurrentCommit  string                                               `json:"current_commit"`
	Scope          string                                               `json:"scope"`
	Transitions    []upstreamV023PostBootstrapSourceSuccessorTransition `json:"transitions"`
	Verification   []string                                             `json:"verification"`
	Safety         upstreamV023PostBootstrapSourceSuccessorSafety       `json:"safety"`
	Result         string                                               `json:"result"`
	IdentitySHA256 string                                               `json:"identity_sha256"`
}

var (
	upstreamV023PostBootstrapSourceSuccessorOnce    sync.Once
	upstreamV023PostBootstrapSourceSuccessorCached  upstreamV023PostBootstrapSourceSuccessorReceipt
	upstreamV023PostBootstrapSourceSuccessorLoadErr error
)

func loadUpstreamV023PostBootstrapSourceSuccessor() (upstreamV023PostBootstrapSourceSuccessorReceipt, error) {
	upstreamV023PostBootstrapSourceSuccessorOnce.Do(func() {
		upstreamV023PostBootstrapSourceSuccessorCached,
			upstreamV023PostBootstrapSourceSuccessorLoadErr =
			readUpstreamV023PostBootstrapSourceSuccessor()
	})
	return upstreamV023PostBootstrapSourceSuccessorCached, upstreamV023PostBootstrapSourceSuccessorLoadErr
}

func readUpstreamV023PostBootstrapSourceSuccessor() (upstreamV023PostBootstrapSourceSuccessorReceipt, error) {
	var receipt upstreamV023PostBootstrapSourceSuccessorReceipt
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(upstreamV023PostBootstrapSourceSuccessorPath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("上游 v0.2.3 post-bootstrap successor 尾部存在额外 JSON")
	}
	var identityDocument map[string]any
	if err := json.Unmarshal(raw, &identityDocument); err != nil {
		return receipt, err
	}
	delete(identityDocument, "identity_sha256")
	canonical, err := json.Marshal(identityDocument)
	if err != nil || upstreamMergeFrameworkDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("上游 v0.2.3 post-bootstrap successor 自摘要不一致")
	}
	if err := validateUpstreamV023PostBootstrapSourceSuccessor(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateUpstreamV023PostBootstrapSourceSuccessor(receipt upstreamV023PostBootstrapSourceSuccessorReceipt) error {
	if receipt.SchemaVersion != "official-egress-upstream-v0.2.3-post-bootstrap-source-successor/v1" ||
		receipt.IssuedAtUTC != "2026-09-10T06:20:00Z" ||
		receipt.BaseCommit != "25f279bd34775f6817ee9c3eec56ad546e263976" ||
		receipt.CurrentCommit != "f0233cc3e5b27f295b12009f5018c6f450faf8ce" ||
		receipt.Scope != "upstream-v0.2.3-post-bootstrap-source-successor" ||
		receipt.Result != "passed_local_evidence_successor" ||
		len(receipt.Transitions) != 15 ||
		!slices.Equal(receipt.Verification, []string{
			"go test ./cmd/egressscan -count=1",
			"go test ./internal/officialegress/... -count=1",
			"go test ./internal/service -count=1",
		}) || receipt.Safety.LiveAccountUsed || receipt.Safety.OfficialEgressProfileChanged ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.WireOrPersonaSelectionChanged ||
		receipt.Safety.DeploymentPerformed {
		return errors.New("上游 v0.2.3 post-bootstrap successor 顶层事实非法")
	}
	if !officialEgressGitObject(receipt.BaseCommit) || !officialEgressGitObject(receipt.CurrentCommit) {
		return errors.New("上游 v0.2.3 post-bootstrap successor 提交摘要非法")
	}
	if err := officialEgressGitAncestor(receipt.BaseCommit, receipt.CurrentCommit); err != nil {
		return errors.New("上游 v0.2.3 post-bootstrap successor 基准提交关系非法")
	}
	if err := officialEgressGitAncestor(receipt.CurrentCommit, "HEAD"); err != nil {
		return errors.New("上游 v0.2.3 post-bootstrap successor 未被当前 HEAD 承接")
	}
	paths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if strings.TrimSpace(transition.Path) == "" || filepath.IsAbs(filepath.FromSlash(transition.Path)) ||
			strings.HasPrefix(filepath.ToSlash(transition.Path), "../") ||
			strings.HasPrefix(filepath.ToSlash(transition.Path), "/") ||
			!receiptSHA256(transition.ToSHA256) || len(transition.PredecessorSHA256s) != 1 ||
			!receiptSHA256(transition.PredecessorSHA256s[0]) ||
			transition.PredecessorSHA256s[0] == transition.ToSHA256 ||
			strings.TrimSpace(transition.Reason) == "" || len(transition.SourceReceipts) == 0 ||
			!slices.IsSorted(transition.SourceReceipts) ||
			len(transition.SourceReceipts) != len(slices.Compact(append([]string(nil), transition.SourceReceipts...))) {
			return errors.New("上游 v0.2.3 post-bootstrap successor 条目非法")
		}
		for _, sourceReceipt := range transition.SourceReceipts {
			if filepath.IsAbs(filepath.FromSlash(sourceReceipt)) || strings.HasPrefix(filepath.ToSlash(sourceReceipt), "../") ||
				strings.HasPrefix(filepath.ToSlash(sourceReceipt), "/") {
				return errors.New("上游 v0.2.3 post-bootstrap successor 来源收据路径非法")
			}
			if _, err := os.Stat(filepath.Join("../../..", filepath.FromSlash(sourceReceipt))); err != nil {
				return errors.New("上游 v0.2.3 post-bootstrap successor 来源收据不存在：" + sourceReceipt)
			}
		}
		currentRaw, currentErr := officialEgressGitShow(receipt.CurrentCommit, transition.Path)
		if currentErr != nil || upstreamMergeFrameworkDigest(currentRaw) != transition.ToSHA256 {
			return errors.New("上游 v0.2.3 post-bootstrap successor 提交源码摘要不一致：" + transition.Path)
		}
		currentWorktree, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		if readErr != nil || upstreamMergeFrameworkDigest(currentWorktree) != transition.ToSHA256 {
			return errors.New("上游 v0.2.3 post-bootstrap successor 当前源码摘要不一致：" + transition.Path)
		}
		paths = append(paths, transition.Path)
	}
	if !slices.IsSorted(paths) || len(paths) != len(slices.Compact(append([]string(nil), paths...))) {
		return errors.New("上游 v0.2.3 post-bootstrap successor 路径未严格排序")
	}
	return nil
}

func officialEgressGitObject(value string) bool {
	return len(value) == 40 && strings.Trim(value, "0123456789abcdef") == ""
}

func officialEgressGitAncestor(before, after string) error {
	command := exec.Command("git", "merge-base", "--is-ancestor", before, after)
	command.Dir = filepath.Join("../../..")
	return command.Run()
}

func officialEgressGitShow(commit, path string) ([]byte, error) {
	command := exec.Command("git", "show", commit+":"+filepath.ToSlash(path))
	command.Dir = filepath.Join("../../..")
	return command.Output()
}

func upstreamV023PostBootstrapSourceSuccessorSupersedes(path, priorDigest, currentDigest string) bool {
	if !receiptSHA256(priorDigest) || !receiptSHA256(currentDigest) || priorDigest == currentDigest {
		return false
	}
	receipt, err := loadUpstreamV023PostBootstrapSourceSuccessor()
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

// auditedSourceSuccessorReaches 在有限且可审计的 successor 图上计算传递闭包。
// 历史收据都是只读的；这里只沿收据中明确登记的 path/from/to 边遍历，遇到
// 未登记摘要、循环或超过边界时保持 fail-close。
func auditedSourceSuccessorReaches(path, priorDigest, currentDigest string) bool {
	if !receiptSHA256(priorDigest) || !receiptSHA256(currentDigest) || priorDigest == currentDigest {
		return false
	}
	queue := []string{priorDigest}
	visited := map[string]struct{}{priorDigest: {}}
	for len(queue) > 0 && len(visited) <= 512 {
		from := queue[0]
		queue = queue[1:]
		for _, to := range auditedSourceSuccessorNext(path, from) {
			if to == currentDigest {
				return true
			}
			if _, seen := visited[to]; seen {
				continue
			}
			visited[to] = struct{}{}
			queue = append(queue, to)
		}
	}
	return false
}

func auditedSourceSuccessorNext(path, from string) []string {
	var next []string
	if receipt, err := loadUpstreamV023PostBootstrapSourceSuccessor(); err == nil {
		for _, transition := range receipt.Transitions {
			if transition.Path == path && slices.Contains(transition.PredecessorSHA256s, from) {
				next = append(next, transition.ToSHA256)
			}
		}
	}
	if entries, err := loadHistoricalSourceDriftEntries(); err == nil {
		if entry, ok := entries[path]; ok && slices.Contains(entry.PredecessorSHA256s, from) {
			next = append(next, entry.HeadSHA256)
		}
	}
	if receipt, err := loadUpstreamV023ScannerSuccessorTransition(); err == nil {
		for _, transition := range receipt.Transitions {
			if transition.Path == path && transition.FromSHA256 == from {
				next = append(next, transition.ToSHA256)
			}
		}
	}
	if receipt, err := loadUpstreamV023SourceTransition(); err == nil {
		for _, entry := range receipt.Entries {
			if entry.Path == path && entry.PredecessorSHA256 != nil && entry.CurrentSHA256 != nil &&
				*entry.PredecessorSHA256 == from {
				next = append(next, *entry.CurrentSHA256)
			}
		}
	}
	if receipt, err := loadCodex0151WorktreeSuccessor(); err == nil {
		for _, entry := range receipt.Entries {
			if entry.Path == path && entry.Before.Existence == "present" && entry.After.Existence == "present" &&
				entry.Before.SHA256 == from && receiptSHA256(entry.After.SHA256) {
				next = append(next, entry.After.SHA256)
			}
		}
	}
	return next
}

func TestUpstreamV023PostBootstrapSourceSuccessorIsFrozen(t *testing.T) {
	if _, err := loadUpstreamV023PostBootstrapSourceSuccessor(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamV023PostBootstrapSourceSuccessorRejectsMutation(t *testing.T) {
	receipt, err := loadUpstreamV023PostBootstrapSourceSuccessor()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]upstreamV023PostBootstrapSourceSuccessorTransition(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateUpstreamV023PostBootstrapSourceSuccessor(mutated); err == nil {
		t.Fatal("变异后的上游 v0.2.3 post-bootstrap successor 被错误接受")
	}
}
