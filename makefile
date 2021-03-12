.PHONY: build clean default test

build: clean
	@go build -o nativeprotect ./cmd/main.go

clean:
	@rm -rf ./nativeprotect

test:
	go test ./...

default: build