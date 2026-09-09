package service

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

const upstreamV023PostBootstrapSourceSuccessorServicePath = "docs/egress/maintenance/upstream-v0.2.3-post-bootstrap-source-successor.json"

type upstreamV023PostBootstrapSourceSuccessorTransitionService struct {
	Path               string   `json:"path"`
	PredecessorSHA256s []string `json:"predecessor_sha256s"`
	ToSHA256           string   `json:"to_sha256"`
	SourceReceipts     []string `json:"source_receipts"`
	Reason             string   `json:"reason"`
}

type upstreamV023PostBootstrapSourceSuccessorSafetyService struct {
	LiveAccountUsed               bool `json:"live_account_used"`
	OfficialEgressProfileChanged  bool `json:"official_egress_profile_changed"`
	ProductionConfigChanged       bool `json:"production_config_changed"`
	WireOrPersonaSelectionChanged bool `json:"wire_or_persona_selection_changed"`
	DeploymentPerformed           bool `json:"deployment_performed"`
}

type upstreamV023PostBootstrapSourceSuccessorReceiptService struct {
	SchemaVersion  string                                                      `json:"schema_version"`
	IssuedAtUTC    string                                                      `json:"issued_at_utc"`
	BaseCommit     string                                                      `json:"base_commit"`
	CurrentCommit  string                                                      `json:"current_commit"`
	Scope          string                                                      `json:"scope"`
	Transitions    []upstreamV023PostBootstrapSourceSuccessorTransitionService `json:"transitions"`
	Verification   []string                                                    `json:"verification"`
	Safety         upstreamV023PostBootstrapSourceSuccessorSafetyService       `json:"safety"`
	Result         string                                                      `json:"result"`
	IdentitySHA256 string                                                      `json:"identity_sha256"`
}

var (
	upstreamV023PostBootstrapSourceSuccessorServiceOnce    sync.Once
	upstreamV023PostBootstrapSourceSuccessorServiceCached  upstreamV023PostBootstrapSourceSuccessorReceiptService
	upstreamV023PostBootstrapSourceSuccessorServiceLoadErr error
)

func loadUpstreamV023PostBootstrapSourceSuccessorService() (upstreamV023PostBootstrapSourceSuccessorReceiptService, error) {
	upstreamV023PostBootstrapSourceSuccessorServiceOnce.Do(func() {
		upstreamV023PostBootstrapSourceSuccessorServiceCached,
			upstreamV023PostBootstrapSourceSuccessorServiceLoadErr =
			readUpstreamV023PostBootstrapSourceSuccessorService()
	})
	return upstreamV023PostBootstrapSourceSuccessorServiceCached, upstreamV023PostBootstrapSourceSuccessorServiceLoadErr
}

func readUpstreamV023PostBootstrapSourceSuccessorService() (upstreamV023PostBootstrapSourceSuccessorReceiptService, error) {
	var receipt upstreamV023PostBootstrapSourceSuccessorReceiptService
	raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(upstreamV023PostBootstrapSourceSuccessorServicePath)))
	if err != nil {
		return receipt, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return receipt, errors.New("service 上游 v0.2.3 post-bootstrap successor 尾部存在额外 JSON")
	}
	var identityDocument map[string]any
	if err := json.Unmarshal(raw, &identityDocument); err != nil {
		return receipt, err
	}
	delete(identityDocument, "identity_sha256")
	canonical, err := json.Marshal(identityDocument)
	if err != nil || upstreamMergeFrameworkServiceDigest(canonical) != receipt.IdentitySHA256 {
		return receipt, errors.New("service 上游 v0.2.3 post-bootstrap successor 自摘要不一致")
	}
	if err := validateUpstreamV023PostBootstrapSourceSuccessorService(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func validateUpstreamV023PostBootstrapSourceSuccessorService(receipt upstreamV023PostBootstrapSourceSuccessorReceiptService) error {
	if receipt.SchemaVersion != "official-egress-upstream-v0.2.3-post-bootstrap-source-successor/v1" ||
		receipt.IssuedAtUTC != "2026-09-10T06:40:00Z" ||
		receipt.BaseCommit != "25f279bd34775f6817ee9c3eec56ad546e263976" ||
		receipt.CurrentCommit != "1dce5ba1f505038b52fea7259b45f40c15731013" ||
		receipt.Scope != "upstream-v0.2.3-post-bootstrap-source-successor" ||
		receipt.Result != "passed_local_evidence_successor" || len(receipt.Transitions) != 15 ||
		!slices.Equal(receipt.Verification, []string{
			"go test ./cmd/egressscan -count=1",
			"go test ./internal/officialegress/... -count=1",
			"go test ./internal/service -count=1",
		}) || receipt.Safety.LiveAccountUsed || receipt.Safety.OfficialEgressProfileChanged ||
		receipt.Safety.ProductionConfigChanged || receipt.Safety.WireOrPersonaSelectionChanged ||
		receipt.Safety.DeploymentPerformed {
		return errors.New("service 上游 v0.2.3 post-bootstrap successor 顶层事实非法")
	}
	if !upstreamV023GitObjectService(receipt.BaseCommit) || !upstreamV023GitObjectService(receipt.CurrentCommit) {
		return errors.New("service 上游 v0.2.3 post-bootstrap successor 提交摘要非法")
	}
	if err := upstreamV023GitAncestorService(receipt.BaseCommit, receipt.CurrentCommit); err != nil {
		return errors.New("service 上游 v0.2.3 post-bootstrap successor 基准提交关系非法")
	}
	if err := upstreamV023GitAncestorService(receipt.CurrentCommit, "HEAD"); err != nil {
		return errors.New("service 上游 v0.2.3 post-bootstrap successor 未被当前 HEAD 承接")
	}
	paths := make([]string, 0, len(receipt.Transitions))
	for _, transition := range receipt.Transitions {
		if strings.TrimSpace(transition.Path) == "" || filepath.IsAbs(filepath.FromSlash(transition.Path)) ||
			strings.HasPrefix(filepath.ToSlash(transition.Path), "../") || strings.HasPrefix(filepath.ToSlash(transition.Path), "/") ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.ToSHA256) || len(transition.PredecessorSHA256s) != 1 ||
			!validOpenAIReplayOOMRepairServiceSHA(transition.PredecessorSHA256s[0]) ||
			transition.PredecessorSHA256s[0] == transition.ToSHA256 || strings.TrimSpace(transition.Reason) == "" ||
			len(transition.SourceReceipts) == 0 || !slices.IsSorted(transition.SourceReceipts) ||
			len(transition.SourceReceipts) != len(slices.Compact(append([]string(nil), transition.SourceReceipts...))) {
			return errors.New("service 上游 v0.2.3 post-bootstrap successor 条目非法")
		}
		for _, sourceReceipt := range transition.SourceReceipts {
			if filepath.IsAbs(filepath.FromSlash(sourceReceipt)) || strings.HasPrefix(filepath.ToSlash(sourceReceipt), "../") || strings.HasPrefix(filepath.ToSlash(sourceReceipt), "/") {
				return errors.New("service 上游 v0.2.3 post-bootstrap successor 来源收据路径非法")
			}
			if _, err := os.Stat(filepath.Join("../../..", filepath.FromSlash(sourceReceipt))); err != nil {
				return errors.New("service 上游 v0.2.3 post-bootstrap successor 来源收据不存在：" + sourceReceipt)
			}
		}
		currentRaw, currentErr := upstreamV023GitShowService(receipt.CurrentCommit, transition.Path)
		if currentErr != nil || upstreamMergeFrameworkServiceDigest(currentRaw) != transition.ToSHA256 {
			return errors.New("service 上游 v0.2.3 post-bootstrap successor 提交源码摘要不一致：" + transition.Path)
		}
		currentWorktree, readErr := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(transition.Path)))
		if readErr != nil || upstreamMergeFrameworkServiceDigest(currentWorktree) != transition.ToSHA256 {
			return errors.New("service 上游 v0.2.3 post-bootstrap successor 当前源码摘要不一致：" + transition.Path)
		}
		paths = append(paths, transition.Path)
	}
	if !slices.IsSorted(paths) || len(paths) != len(slices.Compact(append([]string(nil), paths...))) {
		return errors.New("service 上游 v0.2.3 post-bootstrap successor 路径未严格排序")
	}
	return nil
}

func upstreamV023GitShowService(commit, path string) ([]byte, error) {
	command := exec.Command("git", "show", commit+":"+filepath.ToSlash(path))
	command.Dir = filepath.Join("../../..")
	return command.Output()
}

func upstreamV023PostBootstrapSourceSuccessorSupersedesService(path, priorDigest, currentDigest string) bool {
	if !validOpenAIReplayOOMRepairServiceSHA(priorDigest) || !validOpenAIReplayOOMRepairServiceSHA(currentDigest) || priorDigest == currentDigest {
		return false
	}
	receipt, err := loadUpstreamV023PostBootstrapSourceSuccessorService()
	if err != nil {
		return false
	}
	for _, transition := range receipt.Transitions {
		if transition.Path == path && transition.ToSHA256 == currentDigest && slices.Contains(transition.PredecessorSHA256s, priorDigest) {
			return true
		}
	}
	return false
}

// auditedSourceSuccessorReachesService 在有限且可审计的 successor 图上计算传递闭包。
// service 包独立重放同一组只读收据，避免 officialegress 包通过而 service 漏检。
func auditedSourceSuccessorReachesService(path, priorDigest, currentDigest string) bool {
	if !validOpenAIReplayOOMRepairServiceSHA(priorDigest) ||
		!validOpenAIReplayOOMRepairServiceSHA(currentDigest) || priorDigest == currentDigest {
		return false
	}
	queue := []string{priorDigest}
	visited := map[string]struct{}{priorDigest: {}}
	for len(queue) > 0 && len(visited) <= 512 {
		from := queue[0]
		queue = queue[1:]
		for _, to := range auditedSourceSuccessorNextService(path, from) {
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

type auditedSourceSuccessorEdgeService struct {
	path string
	from string
	to   string
}

var (
	auditedSourceSuccessorEdgesServiceOnce   sync.Once
	auditedSourceSuccessorEdgesServiceCached []auditedSourceSuccessorEdgeService
)

// loadAuditedSourceSuccessorEdgesService 只读取各收据中明确登记的
// path/from/to 边，不调用收据 loader，避免 sync.Once 初始化期间的递归等待。
// 各收据的完整 fail-close 校验仍由其自身 read/validate 函数负责；本函数
// 仅为 successor 闭包提供非递归的边集。
func loadAuditedSourceSuccessorEdgesService() []auditedSourceSuccessorEdgeService {
	auditedSourceSuccessorEdgesServiceOnce.Do(func() {
		appendJSON := func(path string, target any) bool {
			raw, err := os.ReadFile(filepath.Join("../../..", filepath.FromSlash(path)))
			if err != nil {
				return false
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(target); err != nil {
				return false
			}
			return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
		}
		add := func(path, from, to string) {
			if strings.TrimSpace(path) == "" || !validOpenAIReplayOOMRepairServiceSHA(from) ||
				!validOpenAIReplayOOMRepairServiceSHA(to) || from == to {
				return
			}
			auditedSourceSuccessorEdgesServiceCached = append(
				auditedSourceSuccessorEdgesServiceCached,
				auditedSourceSuccessorEdgeService{path: path, from: from, to: to},
			)
		}

		var post upstreamV023PostBootstrapSourceSuccessorReceiptService
		if appendJSON(upstreamV023PostBootstrapSourceSuccessorServicePath, &post) {
			for _, transition := range post.Transitions {
				for _, predecessor := range transition.PredecessorSHA256s {
					add(transition.Path, predecessor, transition.ToSHA256)
				}
			}
		}

		var historical historicalSourceDriftLedger
		if appendJSON(historicalSourceDriftSuccessorPath, &historical) {
			for _, entry := range historical.Entries {
				for _, predecessor := range entry.PredecessorSHA256s {
					add(entry.Path, predecessor, entry.HeadSHA256)
				}
			}
		}

		var scanner upstreamV023ScannerSuccessorReceiptService
		if appendJSON(upstreamV023ScannerSuccessorTransitionServicePath, &scanner) {
			for _, transition := range scanner.Transitions {
				add(transition.Path, transition.FromSHA256, transition.ToSHA256)
			}
		}

		var source upstreamV023SourceTransitionReceiptService
		if appendJSON(upstreamV023SourceTransitionServicePath, &source) {
			for _, entry := range source.Entries {
				if entry.PredecessorSHA256 != nil && entry.CurrentSHA256 != nil {
					add(entry.Path, *entry.PredecessorSHA256, *entry.CurrentSHA256)
				}
			}
		}

		var worktree codex0151WorktreeSuccessorServiceReceipt
		if appendJSON(codex0151WorktreeSuccessorServicePath, &worktree) {
			for _, entry := range worktree.Entries {
				if entry.Before.Existence == "present" && entry.After.Existence == "present" {
					add(entry.Path, entry.Before.SHA256, entry.After.SHA256)
				}
			}
		}

		var frameworkV3 upstreamMergeFrameworkV3ServiceReceipt
		if appendJSON(upstreamMergeFrameworkV3SuccessorServicePath, &frameworkV3) {
			for _, transition := range frameworkV3.Transitions {
				for _, predecessor := range transition.PredecessorSHA256s {
					add(transition.Path, predecessor, transition.ToSHA256)
				}
			}
		}

		var frameworkV4 upstreamMergeFrameworkV4ServiceReceipt
		if appendJSON(upstreamMergeFrameworkV4SuccessorServicePath, &frameworkV4) {
			for _, transition := range frameworkV4.Transitions {
				for _, predecessor := range transition.PredecessorSHA256s {
					add(transition.Path, predecessor, transition.ToSHA256)
				}
			}
		}
	})
	return auditedSourceSuccessorEdgesServiceCached
}

func auditedSourceSuccessorNextService(path, from string) []string {
	var next []string
	for _, edge := range loadAuditedSourceSuccessorEdgesService() {
		if edge.path == path && edge.from == from {
			next = append(next, edge.to)
		}
	}
	return next
}

func TestUpstreamV023PostBootstrapSourceSuccessorServiceIsFrozen(t *testing.T) {
	if _, err := loadUpstreamV023PostBootstrapSourceSuccessorService(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamV023PostBootstrapSourceSuccessorServiceRejectsMutation(t *testing.T) {
	receipt, err := loadUpstreamV023PostBootstrapSourceSuccessorService()
	if err != nil {
		t.Fatal(err)
	}
	mutated := receipt
	mutated.Transitions = append([]upstreamV023PostBootstrapSourceSuccessorTransitionService(nil), receipt.Transitions...)
	mutated.Transitions[0].ToSHA256 = strings.Repeat("0", 64)
	if err := validateUpstreamV023PostBootstrapSourceSuccessorService(mutated); err == nil {
		t.Fatal("变异后的 service 上游 v0.2.3 post-bootstrap successor 被错误接受")
	}
}
