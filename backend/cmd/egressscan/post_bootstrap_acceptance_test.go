package main

import "testing"

func postBootstrapAcceptanceTestRecord(id, function, rationale string) SinkRecord {
	return SinkRecord{
		ScanCandidateID:    id,
		File:               "backend/internal/service/openai_gateway_chat_completions.go",
		Func:               function,
		Package:            "github.com/Wei-Shaw/sub2api/internal/service",
		Callee:             "(*github.com/Wei-Shaw/sub2api/internal/service.OpenAIGatewayService).doOpenAIHTTPUpstreamForRequest",
		Receiver:           "*github.com/Wei-Shaw/sub2api/internal/service.OpenAIGatewayService",
		SinkKind:           "facade_openai_upstream_req",
		Protocol:           "http",
		SinkType:           "facade",
		ASTFingerprint:     "4fa501ed584c",
		Resolution:         TargetUnknown,
		BuildContexts:      []string{"darwin/arm64", "linux/amd64"},
		RuntimeSinkID:      "codex.responses.chat_completions",
		Purpose:            "user_request.chat_completions",
		Persona:            "codex-cli",
		EndpointEvidence:   "codex_profile",
		Routes:             []string{"POST chatgpt.com/backend-api/codex/responses"},
		Backend:            "http_upstream",
		TargetBackend:      "http_upstream",
		EnforcementState:   "legacy_observe",
		Owner:              "czs",
		MigrationChangeset: "3",
		ExpiryCondition:    "变更集 3 迁入 Executor",
		Rationale:          rationale,
	}
}

func postBootstrapAcceptanceFixture() (map[string]SinkRecord, map[string]SinkRecord) {
	transition := reviewedPostBootstrapSinkTransitions[0]
	before := postBootstrapAcceptanceTestRecord(transition.beforeID,
		"*OpenAIGatewayService.ForwardAsChatCompletions", "旧实现")
	after := postBootstrapAcceptanceTestRecord(transition.afterID,
		"*OpenAIGatewayService.forwardAsChatCompletions", "上游内部 helper")
	addition := reviewedPostBootstrapSinkAdditions[0]
	image := SinkRecord{
		ScanCandidateID:  addition.candidateID,
		Persona:          "out-of-scope",
		EndpointEvidence: "not_applicable",
		SinkKind:         "facade_http_upstream_do",
		Backend:          "-",
		TargetBackend:    "-",
		EnforcementState: "not_applicable",
		Rationale:        addition.rationale,
	}
	return map[string]SinkRecord{before.ScanCandidateID: before}, map[string]SinkRecord{
		after.ScanCandidateID: after, image.ScanCandidateID: image,
	}
}

func TestReviewedPostBootstrapSinkTransitionAcceptsExactSuccessor(t *testing.T) {
	transition := reviewedPostBootstrapSinkTransitions[0]
	before := postBootstrapAcceptanceTestRecord(transition.beforeID,
		"*OpenAIGatewayService.ForwardAsChatCompletions", "旧实现")
	after := postBootstrapAcceptanceTestRecord(transition.afterID,
		"*OpenAIGatewayService.forwardAsChatCompletions", "上游内部 helper")
	oldByID, currentByID := postBootstrapAcceptanceFixture()
	accepted, problems := validateReviewedPostBootstrapSinkAcceptance(oldByID, currentByID)
	if len(problems) != 0 {
		t.Fatalf("精确 successor 不应失败：%v", problems)
	}
	if _, ok := accepted.acceptedAdded[after.ScanCandidateID]; !ok {
		t.Fatal("successor 未登记为 accepted addition")
	}
	if _, ok := accepted.acceptedRemoved[before.ScanCandidateID]; !ok {
		t.Fatal("旧 candidate 未登记为 accepted removal")
	}
}

func TestReviewedPostBootstrapSinkTransitionRejectsSemanticMutation(t *testing.T) {
	transition := reviewedPostBootstrapSinkTransitions[0]
	after := postBootstrapAcceptanceTestRecord(transition.afterID,
		"*OpenAIGatewayService.forwardAsChatCompletions", "上游内部 helper")
	after.RuntimeSinkID = "codex.responses.other"
	oldByID, currentByID := postBootstrapAcceptanceFixture()
	currentByID[after.ScanCandidateID] = after
	_, problems := validateReviewedPostBootstrapSinkAcceptance(oldByID, currentByID)
	if len(problems) == 0 {
		t.Fatal("RuntimeSinkID 漂移未被拒绝")
	}
}

func TestReviewedPostBootstrapSinkTransitionRejectsBothGenerations(t *testing.T) {
	transition := reviewedPostBootstrapSinkTransitions[0]
	before := postBootstrapAcceptanceTestRecord(transition.beforeID,
		"*OpenAIGatewayService.ForwardAsChatCompletions", "旧实现")
	oldByID, currentByID := postBootstrapAcceptanceFixture()
	currentByID[before.ScanCandidateID] = before
	_, problems := validateReviewedPostBootstrapSinkAcceptance(oldByID, currentByID)
	if len(problems) == 0 {
		t.Fatal("新旧两代 candidate 并存未被拒绝")
	}
}

func TestReviewedPostBootstrapSinkAdditionIsOutOfScopeAndFailClosed(t *testing.T) {
	addition := reviewedPostBootstrapSinkAdditions[0]
	_, currentByID := postBootstrapAcceptanceFixture()
	current := currentByID[addition.candidateID]
	oldByID, _ := postBootstrapAcceptanceFixture()
	accepted, problems := validateReviewedPostBootstrapSinkAcceptance(oldByID, currentByID)
	if len(problems) != 0 {
		t.Fatalf("范围外新增项不应失败：%v", problems)
	}
	if _, ok := accepted.acceptedAdded[current.ScanCandidateID]; !ok {
		t.Fatal("范围外新增项未被接受")
	}
	current.RuntimeSinkID = "unexpected.runtime"
	currentByID[current.ScanCandidateID] = current
	_, problems = validateReviewedPostBootstrapSinkAcceptance(oldByID, currentByID)
	if len(problems) == 0 {
		t.Fatal("范围外新增项进入运行时身份后未被拒绝")
	}
}
