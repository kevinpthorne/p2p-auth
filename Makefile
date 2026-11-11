.PHONY: all build test clean vendor

all: build test

build:
	mkdir -p bin
	go build -o bin/p2p-auth-server ./cmd/p2p-auth-server
	go build -o bin/p2p-auth-verifier ./cmd/p2p-auth-verifier
	go build -o bin/p2p-auth-client ./cmd/p2p-auth-client

test:
	go test -v -race ./...

vendor:
	go mod tidy && go mod vendor

clean:
	rm -rf bin/
