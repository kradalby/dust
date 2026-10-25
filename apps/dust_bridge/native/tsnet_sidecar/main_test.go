package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/socks5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// Expiry uses Go's monotonic clock, so changing a VM's wall clock cannot test it.
func TestSecretAuthorization(t *testing.T) {
	oldTags := nodeTags
	nodeTags = []string{"tag:dust-node"}
	t.Cleanup(func() {
		stopServingSecrets()
		nodeTags = oldTags
	})
	for _, tt := range []struct {
		name    string
		node    *tailcfg.Node
		expires time.Time
		want    string
	}{
		{"valid", &tailcfg.Node{Tags: nodeTags}, time.Now().Add(time.Hour), "master:cookie"},
		{"expired", &tailcfg.Node{Tags: nodeTags}, time.Now().Add(-time.Second), "ERR: Invalid or expired token"},
		{"untagged", &tailcfg.Node{}, time.Now().Add(time.Hour), "ERR: Peer is not a dust node"},
		{"wrong tag", &tailcfg.Node{Tags: []string{"tag:other"}}, time.Now().Add(time.Hour), "ERR: Peer is not a dust node"},
		{"no identity", nil, time.Now().Add(time.Hour), "ERR: Unauthorized Tailscale Identity"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stopServingSecrets()
			token := strings.Repeat("a", 32)
			inviteTokens[token] = tt.expires
			masterSecrets = []byte("master:cookie")
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/localapi/v0/whois" {
					t.Errorf("unexpected LocalAPI request: %s", r.URL.Path)
				}
				json.NewEncoder(w).Encode(apitype.WhoIsResponse{Node: tt.node})
			}))
			defer api.Close()
			lc := &tailscale.LocalClient{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", api.Listener.Addr().String())
			}}
			request := func() string {
				t.Helper()
				server, client := net.Pipe()
				defer client.Close()
				client.SetDeadline(time.Now().Add(5 * time.Second))
				server.SetDeadline(time.Now().Add(5 * time.Second))
				go handleSecretClient(server, lc)
				go client.Write([]byte(token))
				response, err := io.ReadAll(client)
				if err != nil {
					t.Fatal(err)
				}
				return string(response)
			}
			if got := request(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if tt.name == "valid" {
				if got := request(); got != "ERR: Invalid or expired token" {
					t.Fatalf("replayed token returned %q", got)
				}
			}
		})
	}
}

func TestTagConfiguration(t *testing.T) {
	for _, tt := range []struct {
		env  string
		want string
	}{
		{"", "tag:dust-node"},
		{" , ", "tag:dust-node"},
		{" tag:one, , tag:two ", "tag:one,tag:two"},
	} {
		t.Setenv("TS_TAGS", tt.env)
		if got := strings.Join(getAdvertiseTags(), ","); got != tt.want {
			t.Errorf("TS_TAGS=%q: got %q, want %q", tt.env, got, tt.want)
		}
	}
	oldTags := nodeTags
	nodeTags = []string{"tag:one", "tag:two"}
	t.Cleanup(func() { nodeTags = oldTags })
	for _, tt := range []struct {
		tags []string
		want bool
	}{
		{nil, false},
		{[]string{"tag:one-extra"}, false},
		{[]string{"tag:other"}, false},
		{[]string{"tag:other", "tag:two"}, true},
	} {
		if got := hasMatchingTag(tt.tags); got != tt.want {
			t.Errorf("WhoIs tags %v: got %v, want %v", tt.tags, got, tt.want)
		}
		view := views.SliceOf(tt.tags)
		if got := hasMatchingTagView(&view); got != tt.want {
			t.Errorf("status tags %v: got %v, want %v", tt.tags, got, tt.want)
		}
	}
	if hasMatchingTagView(nil) {
		t.Fatal("missing status tags matched")
	}
}

func TestStartupSOCKSProxy(t *testing.T) {
	if want := os.Getenv("DUST_TEST_PROXY_RESULT"); want != "" {
		// Run the real startup with closed stdin before probing its process-wide dialer.
		main()
		dialer := netns.NewDialer(t.Logf, netmon.NewStatic())
		transport := &http.Transport{DialContext: dialer.DialContext}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get(os.Getenv("DUST_TEST_PROXY_URL"))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != want {
			t.Fatalf("startup dial returned %q, %v; want %q", body, err, want)
		}
		return
	}

	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "direct")
	}))
	defer direct.Close()
	proxied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "proxied")
	}))
	defer proxied.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	proxy := &socks5.Server{
		Logf: func(string, ...any) {},
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, proxied.Listener.Addr().String())
		},
	}
	go proxy.Serve(listener)

	for _, tt := range []struct {
		name, disable, want string
	}{
		{"default", "", "proxied"},
		{"explicit opt-out", "1", "direct"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TS_DISABLE_NETNS", tt.disable)
			t.Setenv("TS_CONTROL_URL", "http://127.0.0.1:1")
			t.Setenv("TS_STATE_DIR", t.TempDir())
			t.Setenv("TS_AUTHKEY", "")
			t.Setenv("TS_NO_LOGS_NO_SUPPORT", "1")
			for _, name := range []string{"ALL_PROXY", "all_proxy"} {
				t.Setenv(name, "socks5://"+listener.Addr().String())
			}
			for _, name := range []string{"NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
				t.Setenv(name, "")
			}
			t.Setenv("DUST_TEST_PROXY_RESULT", tt.want)
			t.Setenv("DUST_TEST_PROXY_URL", direct.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStartupSOCKSProxy$")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("sidecar startup: %v\n%s", err, output)
			}
		})
	}
}

func TestVerifyGrantedTags(t *testing.T) {
	if address := os.Getenv("DUST_TEST_STATUS_ADDRESS"); address != "" {
		nodeTags = []string{"tag:dust-node"}
		verifyTags(&tailscale.LocalClient{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}})
		return
	}
	for _, tt := range []struct {
		name string
		tags []string
		fail bool
	}{
		{"granted", []string{"tag:dust-node"}, false},
		{"missing", nil, true},
		{"mismatched", []string{"tag:other"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/localapi/v0/status" {
					t.Errorf("unexpected LocalAPI request: %s", r.URL.Path)
				}
				json.NewEncoder(w).Encode(map[string]any{"Self": map[string]any{"Tags": tt.tags}})
			}))
			defer api.Close()
			t.Setenv("DUST_TEST_STATUS_ADDRESS", api.Listener.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVerifyGrantedTags$")
			output, err := cmd.CombinedOutput()
			if tt.fail {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(output), "TAG CHECK FAILED") {
					t.Fatalf("missing tag did not stop process: %v\n%s", err, output)
				}
			} else if err != nil || !strings.Contains(string(output), "TAG CHECK OK") {
				t.Fatalf("granted tag rejected: %v\n%s", err, output)
			}
		})
	}
}
