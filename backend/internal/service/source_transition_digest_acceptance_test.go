package service

// codex0151CurrentSourceDigestAcceptedService 只承认已登记的 successor 状态：收据精确目标摘要、
// 当前 0.151 工作区 successor、历史漂移账本，或本次扫描器修复 successor。
// 它不读取目录、不生成新收据，也不会把任意未登记的工作树修改视为合法。
func codex0151CurrentSourceDigestAcceptedService(path, expectedDigest, currentDigest string) bool {
	return expectedDigest == currentDigest ||
		auditedSourceSuccessorReachesService(path, expectedDigest, currentDigest) ||
		upstreamV023PostBootstrapSourceSuccessorSupersedesService(path, expectedDigest, currentDigest) ||
		upstreamMergeFrameworkV3SuccessorSupersedesService(
			path, expectedDigest, currentDigest,
		) ||
		codex0151WorktreeSuccessorEdgeService(path, expectedDigest, currentDigest) ||
		historicalSourceDriftSupersedes(path, expectedDigest, currentDigest) ||
		upstreamV023ScannerSuccessorTransitionSupersedesService(path, expectedDigest, currentDigest) ||
		upstreamV023SourceTransitionSupersedesService(path, expectedDigest, currentDigest)
}
