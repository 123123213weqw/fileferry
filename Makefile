GO ?= go
LDFLAGS := -trimpath -ldflags "-s -w"
# 显式关闭 vendor 模式：本机 GOFLAGS 全局值可能是 -mod=vendor
ENV := CGO_ENABLED=0 GOFLAGS=-mod=mod

.PHONY: all build vet test clean

SRCS := $(shell find cmd internal -name '*.go') go.mod

all: build

build: bin/ff-controller bin/ff-agent bin/ffctl

bin/ff-controller: $(SRCS)
	$(ENV) $(GO) build $(LDFLAGS) -o $@ ./cmd/controller

bin/ff-agent: $(SRCS)
	$(ENV) $(GO) build $(LDFLAGS) -o $@ ./cmd/agent

bin/ffctl: $(SRCS)
	$(ENV) $(GO) build $(LDFLAGS) -o $@ ./cmd/ffctl

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

clean:
	rm -rf bin

# 安全审计：依赖漏洞扫描（govulncheck）
audit:
	GOTOOLCHAIN=auto GOFLAGS=-mod=mod $(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...
