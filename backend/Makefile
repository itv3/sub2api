.PHONY: build generate test test-gate test-unit test-integration test-e2e

VERSION ?= $(shell ./scripts/resolve-version.sh)
LDFLAGS ?= -s -w -X main.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o bin/server ./cmd/server

generate:
	go generate ./ent
	go generate ./cmd/server

test:
	go test ./...
	golangci-lint run ./...

# 上游合并 U-4 full-regression 组使用的本地门禁集合：覆盖 CI test job 的 unit 与
# integration 标签，并固定 -count=1，避免测试缓存掩盖只在 CI 才暴露的失败。
test-gate:
	go test -count=1 ./...
	go test -tags=unit -count=1 ./...
	go test -tags=integration -count=1 ./...
	golangci-lint run ./...

test-unit:
	go test -tags=unit ./...

test-integration:
	go test -tags=integration ./...

test-e2e:
	./scripts/e2e-test.sh

test-e2e-local:
	go test -tags=e2e -v -timeout=300s ./internal/integration/...
