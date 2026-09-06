package officialegress

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/officialegress/bindingcontract"
)

func TestVersionRouteFrozenProfileIsHistoricalOnly(t *testing.T) {
	const retiredDigest = "94071c8eb93cfd337ac6eabc291d878084e3dcec8a9e618e04e6f68792d1a7bc"
	executable, archived, err := loadVersionRouteFrozenProfile(retiredDigest)
	if err != nil || !archived || executable.Version() != "0.147.0" {
		t.Fatalf("历史 version-route 冻结画像无效：archived=%v version=%s err=%v",
			archived, executable.Version(), err)
	}
	for _, mode := range []ReleaseMode{ReleaseModeActive, ReleaseModePrevious} {
		release, resolveErr := DefaultReleaseCatalog().Resolve(mode)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		if release.ProfileDigest() == retiredDigest || release.Version() == "0.147.0" {
			t.Fatalf("历史证明画像被生产 selector 选中：mode=%s version=%s", mode, release.Version())
		}
	}
	if _, found, loadErr := loadVersionRouteFrozenProfile(strings.Repeat("1", 64)); loadErr != nil || found {
		t.Fatalf("未知历史画像未失败关闭：found=%v err=%v", found, loadErr)
	}
}

func TestVersionRouteReceiptBindsCurrentProfilesThatContainEndpoint(t *testing.T) {
	binding, ok := DefaultSinkCatalog().Resolve(SinkCodexQuotaWHAM)
	if !ok || len(binding.Routes()) != 4 {
		t.Fatalf("WHAM 版本 route 未进入最终 Catalog：%+v", binding.Routes())
	}
	resolver, err := NewBundleResolver(DefaultReleaseCatalog(), DefaultSinkCatalog())
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse("https://chatgpt.com/backend-api/wham/settings/user")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []ReleaseMode{ReleaseModeActive, ReleaseModePrevious} {
		targetBundle := versionRouteResolveBundle(t, resolver, mode)
		plan, err := targetBundle.ResolveEndpointPlan(
			SinkCodexQuotaWHAM, "GET", target, WireProtocolHTTP,
		)
		if err != nil || plan.EndpointID() != "wham_settings_user" {
			t.Fatalf("%s/%s 画像未生成 settings/user EndpointPlan：plan=%+v err=%v",
				mode, targetBundle.Version(), plan, err)
		}
	}
}

func TestVersionRouteReceiptFailsClosedOnMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*versionRouteReceiptManifest)
	}{
		{name: "prior receipt", mutate: func(manifest *versionRouteReceiptManifest) {
			manifest.Receipts[0].PriorReceiptDigest = strings.Repeat("0", 64)
		}},
		{name: "profile digest", mutate: func(manifest *versionRouteReceiptManifest) {
			manifest.Receipts[0].ProfileDigests = []string{strings.Repeat("1", 64)}
		}},
		{name: "endpoint evidence", mutate: func(manifest *versionRouteReceiptManifest) {
			manifest.Receipts[0].Route.EvidenceID = "wham_usage"
		}},
		{name: "route absent from every profile", mutate: func(manifest *versionRouteReceiptManifest) {
			manifest.Receipts[0].Route.Route.Path = "/backend-api/wham/not-present"
		}},
		{name: "artifact digest", mutate: func(manifest *versionRouteReceiptManifest) {
			manifest.Receipts[0].Route.WireFixture.SHA256 = strings.Repeat("2", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, evidence, input := versionRouteHistoricalInput(t)
			test.mutate(&manifest)
			if _, err := applyVersionRouteReceipts(manifest, evidence, []SinkBindingInput{input}); err == nil {
				t.Fatal("被篡改的版本 route 收据未失败关闭")
			}
		})
	}
}

func TestVersionRouteReceiptArtifactsBindHistoricalAuthority(t *testing.T) {
	manifest, _, _ := versionRouteHistoricalInput(t)
	document := manifest.Receipts[0]
	if err := verifyVersionRouteReceiptArtifacts(
		versionRouteReceiptFS, document,
		"codex_executor", "wrong-authority", "wrong-issuer",
	); err == nil {
		t.Fatal("版本 route 执行产物未绑定历史 authority")
	}
}

func versionRouteResolveBundle(t *testing.T, resolver *BundleResolver, mode ReleaseMode) ReleaseBundle {
	t.Helper()
	bundle, err := resolver.Resolve(BundleResolveRequest{
		SinkID: SinkCodexQuotaWHAM, Mode: mode,
		Execution: ExecutionPolicy{
			ID: "version-route-test-execution", Source: "test", MaxAttempts: 1,
			Replayable: true, ConcurrencyLimit: 1,
		},
		Deployment: DeploymentSupportPolicy{
			ID: "version-route-test-deployment", Source: "test", Platform: "linux/amd64",
			ProxyMode: "direct", SupportedBackends: []BackendKind{BackendHTTPUpstream},
		},
		Behavior: BehaviorPolicy{
			ID: "version-route-test-behavior", Source: "test",
			Kind: BehaviorUserRequest, AttemptBudget: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func versionRouteHistoricalInput(
	t *testing.T,
) (versionRouteReceiptManifest, map[string]bindingcontract.ReleaseBindingDoc, SinkBindingInput) {
	t.Helper()
	manifest, err := loadVersionRouteReceiptManifest()
	if err != nil || len(manifest.Receipts) != 1 {
		t.Fatalf("加载版本 route 收据：manifest=%+v err=%v", manifest, err)
	}
	document := manifest.Receipts[0]
	binding, ok := DefaultSinkCatalog().Resolve(SinkID(document.SinkID))
	if !ok || binding.migrationReceipt == nil {
		t.Fatal("最终 Catalog 缺少版本 route 目标")
	}
	input := sinkBindingInputForVersionRoute(binding)
	target := versionRouteCatalogRoute(document.Route.Route)
	routes := make([]CatalogRoute, 0, len(input.Routes)-1)
	for _, route := range input.Routes {
		if catalogRouteIdentity(route) != catalogRouteIdentity(target) {
			routes = append(routes, route)
		}
	}
	input.Routes = routes
	receipt := *binding.migrationReceipt
	receipt.routeClaims = append([]migrationRouteClaim(nil), receipt.routeClaims...)
	claims := make([]migrationRouteClaim, 0, len(receipt.routeClaims)-1)
	for _, claim := range receipt.routeClaims {
		if catalogRouteIdentity(claim.route) != catalogRouteIdentity(target) {
			claims = append(claims, claim)
		}
	}
	receipt.routeClaims = claims
	receipt.digest = document.PriorReceiptDigest
	receipt.bindingDigest, err = sinkBindingIdentityDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	input.migrationReceipt = &receipt
	if !receipt.validFor(input) {
		t.Fatal("未能重建版本 route 之前的历史 binding")
	}

	bindingDocument, err := bindingcontract.ParseBindingCatalog(embeddedReleaseBindings)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := bindingcontract.NewBindingCatalog(bindingDocument)
	if err != nil {
		t.Fatal(err)
	}
	evidence, ok := catalog.Resolve(document.SinkID)
	if !ok {
		t.Fatal("ReleaseBinding 缺少 WHAM 证据")
	}
	return manifest, map[string]bindingcontract.ReleaseBindingDoc{document.SinkID: evidence}, input
}
