package agentvault

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http/httpguts"
)

// An HTTP/2 upstream that answers like a gRPC server: it needs "TE: trailers", echoes the brokered header,
// and puts its status in a trailer that is only known once the body is written.
func newGRPCLikeUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "upstream got "+r.Proto, http.StatusHTTPVersionNotSupported)
			return
		}
		if !httpguts.HeaderValuesContainsToken(r.Header.Values("Te"), "trailers") {
			http.Error(w, "missing TE: trailers", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Seen-Tenant", r.Header.Get("X-Tenant"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", "ok")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream
}

// The proxy with HTTP/2 offered for http2Hosts, and a client that tries HTTP/2 through it.
func newHTTP2Proxy(t *testing.T, upstream *httptest.Server, http2Hosts string, services []*resolvedService) *http.Client {
	t.Helper()

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	transport := newUpstreamTransport()
	transport.TLSClientConfig = &tls.Config{RootCAs: upstreamPool}

	ps := &proxyServer{transport: transport, ca: newCaManager(key, cert)}
	if http2Hosts != "" {
		ps.http2Hosts = parseHostPatterns(http2Hosts)
		ps.http2Transport = newHTTP2UpstreamTransport(transport)
	}
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	ps.cache = newSessionCache(fixedResolver{services: services}, ps.pollInterval)

	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)

	clientPool := x509.NewCertPool()
	clientPool.AddCert(cert)
	proxyURL, _ := url.Parse(front.URL)
	proxyURL.User = url.UserPassword(ProxyAuthUsername, "agv_tok")
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{RootCAs: clientPool},
		ForceAttemptHTTP2: true,
	}}
}

func grpcLikeRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	return req
}

func TestHTTP2HostIsBrokeredOverHTTP2WithTrailers(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	svc := policyService(host, nil, nil, []customHeader{{name: "X-Tenant", value: []byte("acme")}}, nil)
	client := newHTTP2Proxy(t, upstream, host, []*resolvedService{svc})

	resp, err := client.Do(grpcLikeRequest(t, "https://"+host+"/grpc.Echo/Call"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.ProtoMajor != 2 {
		t.Fatalf("client leg is %s, want HTTP/2", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Seen-Tenant"); got != "acme" {
		t.Fatalf("upstream saw X-Tenant %q, want the brokered value", got)
	}
	if string(body) != "payload" {
		t.Fatalf("body %q", body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer %q, want 0 (trailers %v)", got, resp.Trailer)
	}
	if got := resp.Trailer.Get("Grpc-Message"); got != "ok" {
		t.Fatalf("Grpc-Message trailer %q", got)
	}
}

func TestHostNotListedStaysHTTP1(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	svc := policyService(host, nil, nil, nil, nil)
	client := newHTTP2Proxy(t, upstream, "other.example.com", []*resolvedService{svc})

	resp, err := client.Do(grpcLikeRequest(t, "https://"+host+"/grpc.Echo/Call"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Fatalf("client leg is %s for a host not listed, want HTTP/1.1", resp.Proto)
	}
	// The HTTP/1.1 path is unchanged: it does not ask the upstream for HTTP/2, so this upstream refuses.
	if resp.StatusCode != http.StatusHTTPVersionNotSupported {
		t.Fatalf("status %d, want the upstream's 505 for an HTTP/1.1 request", resp.StatusCode)
	}
}

// An HTTP/2 upstream that echoes each chunk as it arrives, as a bidi gRPC server answers each message before
// the client sends the next.
func newBidiEchoUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Seen-Authorization", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buf := make([]byte, 64)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				w.(http.Flusher).Flush()
			}
			if err != nil {
				break
			}
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+HeaderDecision, "spoofed")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream
}

// Sends two messages, each only after the reply to the one before, so a proxy that waits for the end of the
// request body never answers.
func bidiRoundTrip(t *testing.T, client *http.Client, target string) *http.Response {
	t.Helper()
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, target, pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")

	done := make(chan *http.Response, 1)
	failed := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			failed <- err
			return
		}
		for _, msg := range []string{"first", "second"} {
			if _, err := io.WriteString(pw, msg); err != nil {
				failed <- err
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(resp.Body, got); err != nil || string(got) != msg {
				failed <- fmt.Errorf("reply %q, %v; want %q", got, err, msg)
				return
			}
		}
		_ = pw.Close()
		if rest, _ := io.ReadAll(resp.Body); len(rest) != 0 {
			failed <- fmt.Errorf("unexpected trailing body %q", rest)
			return
		}
		done <- resp
	}()
	select {
	case resp := <-done:
		return resp
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		_ = pw.CloseWithError(errors.New("timed out"))
		t.Fatal("the bidi call did not get a reply to its first message")
	}
	return nil
}

func TestBidiGRPCStreamsThroughARefreshableCredential(t *testing.T) {
	upstream := newBidiEchoUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	svc := policyService(host, nil, nil, nil, nil)
	svc.credential = oauthToken("oauth-access-token")
	client := newHTTP2Proxy(t, upstream, host, []*resolvedService{svc})

	resp := bidiRoundTrip(t, client, "https://"+host+"/grpc.Echo/Chat")
	if got := resp.Header.Get("X-Seen-Authorization"); got != "Bearer oauth-access-token" {
		t.Fatalf("upstream saw Authorization %q", got)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("Grpc-Status trailer %q", got)
	}
	if got := resp.Trailer.Get(HeaderDecision); got != "" {
		t.Fatalf("the upstream set the proxy's own %s trailer to %q", HeaderDecision, got)
	}
}

func TestBidiGRPCStreamsThroughAHook(t *testing.T) {
	upstream := newBidiEchoUpstream(t)
	host := strings.TrimPrefix(upstream.URL, "https://")
	fake := newFakeHook(t, answerHook(`{"decision":"allow"}`))
	svc := policyService(host, nil, nil, nil, nil)
	svc.id, svc.accessBundleID = "svc-1", "bundle-1"
	svc.hook = fake.hook()
	client := newHTTP2Proxy(t, upstream, host, []*resolvedService{svc})

	bidiRoundTrip(t, client, "https://"+host+"/grpc.Echo/Chat")
	req := fake.only(t).payload(t).Request
	if req == nil || req.Method != http.MethodPost || !req.BodyTruncated || req.Body != "" {
		t.Fatalf("hook was asked with %+v, want the call with no body, marked truncated", req)
	}
}

func TestHTTP2StreamMayStayQuietBetweenWrites(t *testing.T) {
	rec := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	w := &flushingWriter{ResponseWriter: rec, rc: http.NewResponseController(rec), quietAllowed: true}
	if _, err := io.WriteString(w, "message"); err != nil {
		t.Fatal(err)
	}
	if len(rec.deadlines) != 2 || rec.deadlines[0].IsZero() || !rec.deadlines[1].IsZero() {
		t.Fatalf("deadlines %v, want one bounding the write and then none", rec.deadlines)
	}
}

func TestHTTP2UpstreamKeepsTheSOCKS5PrivateDestinationGuard(t *testing.T) {
	upstream := newGRPCLikeUpstream(t)
	guarded, err := newGuardedUpstreamTransport()
	if err != nil {
		t.Fatal(err)
	}
	guarded.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	_, err = newHTTP2UpstreamTransport(guarded).RoundTrip(grpcLikeRequest(t, upstream.URL+"/grpc.Echo/Call"))
	if !errors.Is(err, errPrivateDestination) {
		t.Fatalf("got %v, want %v", err, errPrivateDestination)
	}
}
