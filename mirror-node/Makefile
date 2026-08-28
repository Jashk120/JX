.PHONY: build vet test proto fmt tidy clean blst

build:
	CGO_ENABLED=1 go build ./...

vet:
	CGO_ENABLED=1 go vet ./...

test:
	CGO_ENABLED=1 go test ./...

blst:
	@echo "Building blst static library (requires gcc, CGO)..."
	@echo "Linux: go build uses embedded C sources via cgo_server.c + CGO_CFLAGS automatically."
	@echo "No separate libblst.a is needed; github.com/supranational/blst builds via cgo."
	@echo "If you see illegal-instruction crashes on older CPUs, rebuild with:"
	@echo "  CGO_CFLAGS=\"-O2 -D__BLST_PORTABLE__\" CGO_ENABLED=1 go build ./..."
	@go list -m github.com/supranational/blst

proto:
	protoc --proto_path=../proto \
		--go_out=internal/stream/pb \
		--go_opt=Mjkain_stream.proto=github.com/JKaIN/mirror-node/internal/stream/pb \
		--go_opt=paths=source_relative \
		../proto/jkain_stream.proto

fmt:
	go fmt ./...

tidy:
	go mod tidy

clean:
	go clean -cache -testcache
	rm -f mirrord
