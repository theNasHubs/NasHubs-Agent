package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Helper images are pinned by digest so a re-tagged or compromised upstream
// tag cannot change what the agent runs with access to the Docker daemon.
// To update: `docker buildx imagetools inspect <image>:<tag>` and copy the
// index digest (multi-arch, so the same pin works on amd64 and arm64 NAS).
const (
	helperImage      = "alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
	cloudflaredImage = "cloudflare/cloudflared:2026.10.1@sha256:a15a3b50b8dabd57ac2090e9484c0247dba9dfa1f0df4d298d4317f9d69eb2d5"
)

var imageDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// imageRepo strips the tag and digest from an image reference:
// "ghcr.io/o/a:latest" → "ghcr.io/o/a", "host:5000/a@sha256:…" → "host:5000/a".
func imageRepo(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref = ref[:i]
	}
	return ref
}

// normalizeRepo makes Docker Hub names comparable: Docker reports
// "docker.io/library/alpine" as "alpine" in RepoDigests.
func normalizeRepo(repo string) string {
	for _, p := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		repo = strings.TrimPrefix(repo, p)
	}
	return strings.TrimPrefix(repo, "library/")
}

// pinnedRef returns repo@digest for the given image, validating the digest.
func pinnedRef(image, digest string) (string, error) {
	if !imageDigest.MatchString(digest) {
		return "", fmt.Errorf("digest must be sha256:<64 lowercase hex>")
	}
	return imageRepo(image) + "@" + digest, nil
}
