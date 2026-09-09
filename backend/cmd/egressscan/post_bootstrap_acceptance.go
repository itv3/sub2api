package main

import "fmt"

// postBootstrapSinkTransition 描述上游合并后同一发送语义的精确 successor。
//
// 它与 infrastructure transition 不同：successor 可以仍然是业务 persona，
// 例如上游把一个公开 facade 重构为内部 helper。只有指定的旧 candidate 被
// 当前指定的新 candidate 完整替换，且稳定发送语义保持不变时，才能接受这类变化。
type postBootstrapSinkTransition struct {
	name        string
	beforeID    string
	afterID     string
	evidenceRef string
	rationale   string
}

// postBootstrapSinkAddition 描述上游合并后新增、但不进入官方 OAuth Catalog 的
// 发送点。它不能用“按文件全部 out-of-scope”替代，必须精确到 ScanCandidateID，
// 并冻结运行时身份为空、not_applicable 等安全边界。
type postBootstrapSinkAddition struct {
	name             string
	candidateID      string
	persona          string
	runtimeSinkID    string
	purpose          string
	endpointEvidence string
	sinkKind         string
	backend          string
	targetBackend    string
	enforcementState string
	evidenceRef      string
	rationale        string
}

type postBootstrapAcceptance struct {
	acceptedAdded   map[string]struct{}
	acceptedRemoved map[string]struct{}
}

var upstreamScannerSuccessorEvidence = fmt.Sprintf(
	"docs/egress/maintenance/upstream-v%d.%d.%d-scanner-successor-source-transition.json",
	0, 2, 3,
)

var reviewedPostBootstrapSinkTransitions = []postBootstrapSinkTransition{
	{
		name:        "upstream-chat-completions-facade-successor",
		beforeID:    "github.com/Wei-Shaw/sub2api/internal/service.*OpenAIGatewayService.ForwardAsChatCompletions@backend/internal/service/openai_gateway_chat_completions.go#facade_openai_upstream_req#1",
		afterID:     "github.com/Wei-Shaw/sub2api/internal/service.*OpenAIGatewayService.forwardAsChatCompletions@backend/internal/service/openai_gateway_chat_completions.go#facade_openai_upstream_req#1",
		evidenceRef: upstreamScannerSuccessorEvidence,
		rationale:   "本次上游版本将 Chat Completions 出站实现移入内部 helper；RuntimeSinkID、路由、后端与 AST 指纹保持不变。",
	},
}

var reviewedPostBootstrapSinkAdditions = []postBootstrapSinkAddition{
	{
		name:             "upstream-image-url-b64-backfill",
		candidateID:      "github.com/Wei-Shaw/sub2api/internal/service.*OpenAIGatewayService.fetchOpenAIImageURLBase64@backend/internal/service/openai_images_b64_backfill.go#facade_http_upstream_do#1",
		persona:          "out-of-scope",
		runtimeSinkID:    "",
		purpose:          "",
		endpointEvidence: "not_applicable",
		sinkKind:         "facade_http_upstream_do",
		backend:          "-",
		targetBackend:    "-",
		enforcementState: "not_applicable",
		evidenceRef:      upstreamScannerSuccessorEvidence,
		rationale:        "本次上游版本新增图片 URL 到 b64_json 的兼容回填下载，不承载官方 OAuth 出站。",
	},
}

// validateReviewedPostBootstrapSinkAcceptance 只接受明确登记的 upstream successor。
// 任何缺失、并存、语义变化或安全边界变化都会返回问题；调用方不能通过分类规则
// 或 removal receipt 静默绕过这些检查。
func validateReviewedPostBootstrapSinkAcceptance(
	oldByID, currentByID map[string]SinkRecord,
) (postBootstrapAcceptance, []string) {
	accepted := postBootstrapAcceptance{
		acceptedAdded:   make(map[string]struct{}),
		acceptedRemoved: make(map[string]struct{}),
	}
	var problems []string

	for _, transition := range reviewedPostBootstrapSinkTransitions {
		if transition.name == "" || transition.beforeID == "" || transition.afterID == "" ||
			transition.beforeID == transition.afterID || transition.evidenceRef == "" ||
			transition.rationale == "" {
			problems = append(problems, "post-bootstrap sink transition 定义不完整")
			continue
		}
		before, beforeExists := oldByID[transition.beforeID]
		after, afterExists := currentByID[transition.afterID]
		if !beforeExists {
			problems = append(problems, fmt.Sprintf(
				"%s 旧 candidate 不在 bootstrap 基线中: %s", transition.name, transition.beforeID))
			continue
		}
		if !afterExists {
			problems = append(problems, fmt.Sprintf(
				"%s successor candidate 不在当前发送面中: %s", transition.name, transition.afterID))
			continue
		}
		if _, stillPresent := currentByID[transition.beforeID]; stillPresent {
			problems = append(problems, fmt.Sprintf(
				"%s 新旧 candidate 不能同时存在", transition.name))
			continue
		}
		if err := validatePostBootstrapSinkSuccessor(before, after); err != nil {
			problems = append(problems, fmt.Sprintf("%s successor 语义不一致：%v", transition.name, err))
			continue
		}
		accepted.acceptedAdded[transition.afterID] = struct{}{}
		accepted.acceptedRemoved[transition.beforeID] = struct{}{}
	}

	for _, addition := range reviewedPostBootstrapSinkAdditions {
		if addition.name == "" || addition.candidateID == "" || addition.evidenceRef == "" ||
			addition.rationale == "" {
			problems = append(problems, "post-bootstrap sink addition 定义不完整")
			continue
		}
		if _, existed := oldByID[addition.candidateID]; existed {
			problems = append(problems, fmt.Sprintf(
				"%s 被错误登记为 bootstrap 后新增，但 candidate 已存在: %s",
				addition.name, addition.candidateID))
			continue
		}
		current, exists := currentByID[addition.candidateID]
		if !exists {
			problems = append(problems, fmt.Sprintf(
				"%s 新增 candidate 不在当前发送面中: %s", addition.name, addition.candidateID))
			continue
		}
		if err := validatePostBootstrapSinkAddition(addition, current); err != nil {
			problems = append(problems, fmt.Sprintf("%s 新增 candidate 不安全：%v", addition.name, err))
			continue
		}
		accepted.acceptedAdded[addition.candidateID] = struct{}{}
	}

	return accepted, problems
}

// validatePostBootstrapSinkSuccessor 比较除 candidate 身份、函数名、行号和审阅
// 说明外的全部字段。这样允许上游做机械 helper 重命名，但不能偷偷改变 route、
// RuntimeSinkID、AST 指纹、后端、Persona 或构建矩阵。
func validatePostBootstrapSinkSuccessor(before, after SinkRecord) error {
	left := before
	right := after
	left.ScanCandidateID, right.ScanCandidateID = "", ""
	left.Func, right.Func = "", ""
	left.Rationale, right.Rationale = "", ""
	left.Line, right.Line = 0, 0
	if !sameFrozenCandidate(left, right) {
		return fmt.Errorf("稳定字段发生变化")
	}
	if after.RuntimeSinkID == "" || after.Persona == "" || after.EnforcementState == "" {
		return fmt.Errorf("successor 缺少运行时身份或分类状态")
	}
	return nil
}

func validatePostBootstrapSinkAddition(expected postBootstrapSinkAddition, current SinkRecord) error {
	if current.ScanCandidateID != expected.candidateID || current.Persona != expected.persona ||
		current.RuntimeSinkID != expected.runtimeSinkID || current.Purpose != expected.purpose ||
		current.EndpointEvidence != expected.endpointEvidence || current.SinkKind != expected.sinkKind ||
		current.Backend != expected.backend || current.TargetBackend != expected.targetBackend ||
		current.EnforcementState != expected.enforcementState || current.Rationale == "" {
		return fmt.Errorf("分类、运行时身份或后端边界与审核收据不一致")
	}
	if current.Persona == "out-of-scope" &&
		(current.RuntimeSinkID != "" || current.EnforcementState != "not_applicable") {
		return fmt.Errorf("out-of-scope candidate 不能进入运行时 Catalog")
	}
	return nil
}
