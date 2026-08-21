.PHONY: build vet test proto fmt tidy clean

build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

proto:
	protoc --proto_path=proto --go_out=internal/stream/pb --go_opt=paths=source_relative proto/jkain_stream.proto

fmt:
	go fmt ./...

tidy:
	go mod tidy

clean:
	go clean -cache -testcache
	rm -f mirrord
