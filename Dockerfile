# syntax=docker/dockerfile:1

# ---- stage 1: build a static binary per target arch ----
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# CGO disabled → fully static, runs on any linux/{arm64,amd64} base.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nashubs-agent .

# ---- stage 2: runtime ----
# docker:27-cli bundles the `docker` CLI + the compose plugin. The agent shells
# out to `docker compose`, talking to the HOST daemon through the mounted socket
# (/var/run/docker.sock). No daemon runs inside this container.
FROM docker:27-cli
RUN apk add --no-cache ca-certificates nginx
COPY --from=build /out/nashubs-agent /usr/local/bin/nashubs-agent

# /data is the NAS host docker share, mounted at runtime:
#   -v /volume1/docker:/data -v /var/run/docker.sock:/var/run/docker.sock
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["nashubs-agent"]
