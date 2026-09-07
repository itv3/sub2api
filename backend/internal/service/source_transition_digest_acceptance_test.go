package service

// codex0151CurrentSourceDigestAcceptedService 只承认三种已登记状态：收据精确目标摘要、
// 当前 0.151 工作区 successor 的 after 摘要，或历史漂移账本登记的 head 摘要。
// 它不读取目录、不生成新收据，也不会把任意未登记的工作树修改视为合法。
func codex0151CurrentSourceDigestAcceptedService(path, expectedDigest, currentDigest string) bool {
	return expectedDigest == currentDigest ||
		codex0151WorktreeSuccessorEdgeService(path, expectedDigest, currentDigest) ||
		historicalSourceDriftSupersedes(path, expectedDigest, currentDigest)
}
