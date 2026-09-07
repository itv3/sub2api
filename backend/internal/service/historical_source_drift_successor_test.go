package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"testing"
)

const historicalSourceDriftSuccessorPath = "docs/egress/maintenance/historical-source-drift-successor.json"

var historicalSourceDriftSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type historicalSourceDriftPolicy struct {
	WorktreeChangesAllowed bool   `json:"worktree_changes_allowed"`
	ReceiptRewriteAllowed  bool   `json:"receipt_rewrite_allowed"`
	Reason                 string `json:"reason"`
}

type historicalSourceDriftEntry struct {
	Path               string   `json:"path"`
	PredecessorSHA256s []string `json:"predecessor_sha256s"`
	HeadSHA256         string   `json:"head_sha256"`
	SourceReceipts     []string `json:"source_receipts"`
	Reason             string   `json:"reason"`
}

type historicalSourceDriftLedger struct {
	SchemaVersion  string                       `json:"schema_version"`
	IssuedAtUTC    string                       `json:"issued_at_utc"`
	BaseCommit     string                       `json:"base_commit"`
	Scope          string                       `json:"scope"`
	Policy         historicalSourceDriftPolicy  `json:"policy"`
	Entries        []historicalSourceDriftEntry `json:"entries"`
	IdentitySHA256 string                       `json:"identity_sha256"`
}

type historicalSourceDriftIdentity struct {
	SchemaVersion string                       `json:"schema_version"`
	IssuedAtUTC   string                       `json:"issued_at_utc"`
	BaseCommit    string                       `json:"base_commit"`
	Scope         string                       `json:"scope"`
	Policy        historicalSourceDriftPolicy  `json:"policy"`
	Entries       []historicalSourceDriftEntry `json:"entries"`
}

var (
	historicalSourceDriftOnce    sync.Once
	historicalSourceDriftEntries map[string]historicalSourceDriftEntry
	historicalSourceDriftErr     error
)

func loadHistoricalSourceDriftEntries() (map[string]historicalSourceDriftEntry, error) {
	historicalSourceDriftOnce.Do(func() {
		raw, err := os.ReadFile(filepath.Join("../../..", historicalSourceDriftSuccessorPath))
		if err != nil {
			historicalSourceDriftErr = err
			return
		}
		var ledger historicalSourceDriftLedger
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&ledger); err != nil {
			historicalSourceDriftErr = err
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			historicalSourceDriftErr = errors.New("历史漂移 successor ledger 尾部存在额外 JSON")
			return
		}
		if ledger.SchemaVersion != "official-egress-historical-source-drift-successor/v1" ||
			ledger.IssuedAtUTC == "" || !historicalSourceDriftCommitSHA256(ledger.BaseCommit) ||
			ledger.Scope != "head-historical-source-drift" ||
			ledger.Policy.WorktreeChangesAllowed || ledger.Policy.ReceiptRewriteAllowed ||
			ledger.Policy.Reason == "" || len(ledger.Entries) == 0 ||
			!historicalSourceDriftSHA256.MatchString(ledger.IdentitySHA256) {
			historicalSourceDriftErr = errors.New("历史漂移 successor ledger 顶层事实非法")
			return
		}
		identityRaw, err := json.Marshal(historicalSourceDriftIdentity{
			SchemaVersion: ledger.SchemaVersion,
			IssuedAtUTC:   ledger.IssuedAtUTC,
			BaseCommit:    ledger.BaseCommit,
			Scope:         ledger.Scope,
			Policy:        ledger.Policy,
			Entries:       ledger.Entries,
		})
		if err != nil {
			historicalSourceDriftErr = err
			return
		}
		identityRaw = append(identityRaw, '\n')
		sum := sha256.Sum256(identityRaw)
		if hex.EncodeToString(sum[:]) != ledger.IdentitySHA256 {
			historicalSourceDriftErr = errors.New("历史漂移 successor ledger 自摘要不一致")
			return
		}
		entries := make(map[string]historicalSourceDriftEntry, len(ledger.Entries))
		paths := make([]string, 0, len(ledger.Entries))
		for _, entry := range ledger.Entries {
			if entry.Path == "" || filepath.IsAbs(filepath.FromSlash(entry.Path)) ||
				len(entry.Path) >= 3 && entry.Path[:3] == "../" ||
				entry.Path[:1] == "/" ||
				!historicalSourceDriftSHA256.MatchString(entry.HeadSHA256) ||
				entry.Reason == "" || len(entry.PredecessorSHA256s) == 0 ||
				len(entry.SourceReceipts) == 0 || !sort.StringsAreSorted(entry.PredecessorSHA256s) ||
				!sort.StringsAreSorted(entry.SourceReceipts) {
				historicalSourceDriftErr = errors.New("历史漂移 successor ledger 条目非法")
				return
			}
			for index, predecessor := range entry.PredecessorSHA256s {
				if !historicalSourceDriftSHA256.MatchString(predecessor) || predecessor == entry.HeadSHA256 ||
					(index > 0 && predecessor == entry.PredecessorSHA256s[index-1]) {
					historicalSourceDriftErr = errors.New("历史漂移 successor ledger 前序摘要非法")
					return
				}
			}
			for index, receipt := range entry.SourceReceipts {
				if receipt == "" || filepath.IsAbs(filepath.FromSlash(receipt)) ||
					len(receipt) >= 3 && receipt[:3] == "../" ||
					(index > 0 && receipt == entry.SourceReceipts[index-1]) {
					historicalSourceDriftErr = errors.New("历史漂移 successor ledger 来源收据非法")
					return
				}
			}
			if _, duplicate := entries[entry.Path]; duplicate {
				historicalSourceDriftErr = errors.New("历史漂移 successor ledger 路径重复")
				return
			}
			current, readErr := historicalSourceDriftReadBaseCommit(ledger.BaseCommit, entry.Path)
			if readErr != nil || sha256HexHistorical(current) != entry.HeadSHA256 {
				historicalSourceDriftErr = errors.New("历史漂移 successor ledger 基准提交源码摘要不一致：" + entry.Path)
				return
			}
			entries[entry.Path] = entry
			paths = append(paths, entry.Path)
		}
		if !sort.StringsAreSorted(paths) {
			historicalSourceDriftErr = errors.New("历史漂移 successor ledger 路径未排序")
			return
		}
		historicalSourceDriftEntries = entries
	})
	return historicalSourceDriftEntries, historicalSourceDriftErr
}

func historicalSourceDriftCommitSHA256(commit string) bool {
	if len(commit) != 40 {
		return false
	}
	for _, char := range commit {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}

func historicalSourceDriftReadBaseCommit(commit, sourcePath string) ([]byte, error) {
	command := exec.Command("git", "show", commit+":"+filepath.ToSlash(sourcePath))
	command.Dir = filepath.Join("../../..")
	return command.Output()
}

func historicalSourceDriftSupersedes(path, priorDigest, currentDigest string) bool {
	if !historicalSourceDriftSHA256.MatchString(priorDigest) ||
		!historicalSourceDriftSHA256.MatchString(currentDigest) || priorDigest == currentDigest {
		return false
	}
	entries, err := loadHistoricalSourceDriftEntries()
	if err != nil {
		return false
	}
	entry, ok := entries[path]
	if !ok || entry.HeadSHA256 != currentDigest {
		return false
	}
	for _, predecessor := range entry.PredecessorSHA256s {
		if predecessor == priorDigest {
			return true
		}
	}
	return false
}

func sha256HexHistorical(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestHistoricalSourceDriftSuccessorLedgerIsFrozen(t *testing.T) {
	entries, err := loadHistoricalSourceDriftEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 278 {
		t.Fatalf("历史漂移 successor ledger 条目数=%d，期望 278", len(entries))
	}
}
