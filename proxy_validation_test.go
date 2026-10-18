package main

import "testing"

func TestValidAppProxy(t *testing.T) {
	ok := []string{"/jellyfin", "/apps/qbittorrent", "/apps/hello-world", "/MyApp", "/a_b/c-d"}
	for _, p := range ok {
		if !validAppProxy(p, 8096) {
			t.Errorf("expected %q to be accepted", p)
		}
	}
	bad := []string{
		"", "/", "jellyfin", "/a/", "//a", "/a b", "/a;b", "/a{", "/a}", "/a\nb", "/a$b", "/a/../b", "/a.b",
		"/a { } location ^~ /x/ { alias /; autoindex on; } location = /b",
	}
	for _, p := range bad {
		if validAppProxy(p, 8096) {
			t.Errorf("expected %q to be rejected", p)
		}
	}
	for _, port := range []int{0, -1, 65536, 70000} {
		if validAppProxy("/jellyfin", port) {
			t.Errorf("expected port %d to be rejected", port)
		}
	}
}
