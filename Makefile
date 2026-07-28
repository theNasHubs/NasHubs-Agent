# Nasdeck Agent — build helpers.
# Requires Go for local build; Docker buildx for multi-arch images.

IMAGE   ?= ghcr.io/phuctu1901/nasdeck-agent
TAG     ?= latest
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build run docker multiarch clean test

## build: compile a native binary into ./bin
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/nasdeck-agent .

## run: run locally for dev (binds :8443, data in ./tmp-data)
run: build
	mkdir -p tmp-data
	NASDECK_DATA_DIR=./tmp-data \
	NASDECK_HOST_DATA_DIR=/volume1/docker \
	NASDECK_TRUSTED_PUBKEY="$${NASDECK_TRUSTED_PUBKEY:-}" \
	NASDECK_PAIRING_SECRET="$${NASDECK_PAIRING_SECRET:-devsecret}" \
	./bin/nasdeck-agent

## docker: build the image for the host arch
docker:
	docker build -t $(IMAGE):$(TAG) .

## multiarch: build + push linux/arm64 + linux/amd64 (needs buildx, login to registry)
multiarch:
	docker buildx build \
		--platform linux/arm64,linux/amd64 \
		-t $(IMAGE):$(TAG) -t $(IMAGE):$(VERSION) \
		--push .

## test: run unit tests (incl. signature interop vectors)
test:
	go test ./...

clean:
	rm -rf bin tmp-data
