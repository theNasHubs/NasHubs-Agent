# syntax=docker/dockerfile:1

# ---- stage 1: cross-compile a static binary for the target arch ----
# Pin the build stage to the BUILDER's native arch (fast) and cross-compile to
# the requested target with GOOS/GOARCH — this makes `docker buildx --platform
# linux/amd64,linux/arm64` build quickly without QEMU emulating the compiler.
# Base images are pinned by digest (multi-arch index); bump tag and digest together.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src

# Copy module manifests first for layer caching; go.sum is required for a
# verified, reproducible `go mod download` / build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# buildx injects these automatically per target platform.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
# CGO disabled → fully static, runs on any linux/{amd64,arm64} base.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/nashubs-agent .

# ---- stage 2: runtime ----
# docker:27-cli bundles the `docker` CLI + the compose plugin. The agent shells
# out to `docker compose`, talking to the HOST daemon through the mounted socket
# (/var/run/docker.sock). No daemon runs inside this container.
FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c

# Auto-links the GHCR package to its source repo (replaces the old manual
# "Connect repository" button) and shows up on the package page.
LABEL org.opencontainers.image.source="https://github.com/theNasHubs/NasHubs-Agent"
LABEL org.opencontainers.image.description="NasHubs Agent — on-NAS control plane (deploy, reverse proxy, remote access)."
LABEL org.opencontainers.image.licenses="proprietary"

RUN apk add --no-cache ca-certificates nginx
COPY --from=build /out/nashubs-agent /usr/local/bin/nashubs-agent

# /data is the NAS host docker share, mounted at runtime:
#   -v /volume1/docker:/data -v /var/run/docker.sock:/var/run/docker.sock
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["nashubs-agent"]
