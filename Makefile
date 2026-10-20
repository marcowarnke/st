VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/marcowarnke/st/internal/cmd.Version=$(VERSION)
PLATFORMS := windows/amd64 linux/amd64 darwin/arm64

.PHONY: build install test dist clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/st .

install:
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' .

test:
	go test ./...

dist:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "dist/st_$${os}_$${arch}$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/st_$${os}_$${arch}$$ext . || exit 1; \
	done

clean:
	rm -rf bin dist
