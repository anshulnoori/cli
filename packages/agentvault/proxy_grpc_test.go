package agentvault

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// A real grpc-go client and server, because net/http cannot show whether a trailers-only reply reached the
// client as the single frame gRPC needs.
func TestRealGRPCThroughTheProxy(t *testing.T) {
	upKey, upCert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := newCaManager(upKey, upCert).mintLeaf("grpc.test")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewServerTLSFromCert(&leaf)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if md, _ := metadata.FromIncomingContext(ctx); len(md.Get("x-tenant")) != 1 || md.Get("x-tenant")[0] != "acme" {
				return nil, status.Error(codes.Unauthenticated, "no brokered header")
			}
			return h(ctx, req)
		}),
	)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	target := "grpc.test:" + port

	upPool := x509.NewCertPool()
	upPool.AddCert(upCert)
	transport := newUpstreamTransport()
	transport.TLSClientConfig = &tls.Config{RootCAs: upPool}
	// grpc.test is not in DNS; the proxy reaches it on loopback.
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, lis.Addr().String())
	}
	key, cert, err := generateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	ps := &proxyServer{transport: transport, ca: newCaManager(key, cert)}
	ps.http2Hosts = parseHostPatterns(target)
	ps.http2Transport = newHTTP2UpstreamTransport(transport)
	ps.setConfig(ProxyConfig{TrafficPolicy: TrafficPolicyAnyHost})
	svc := policyService(target, nil, nil, []customHeader{{name: "X-Tenant", value: []byte("acme")}}, nil)
	ps.cache = newSessionCache(fixedResolver{services: []*resolvedService{svc}}, ps.pollInterval)
	front := httptest.NewServer(http.HandlerFunc(ps.dispatch))
	t.Cleanup(front.Close)

	connectThroughProxy := func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", front.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		auth := base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername + ":agv_tok"))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", addr, addr, auth)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("CONNECT: %v %v", resp, err)
		}
		return conn, nil
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(cert)
	conn, err := grpc.NewClient("passthrough:///"+target,
		grpc.WithContextDialer(connectThroughProxy),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: clientPool, ServerName: "grpc.test"})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := healthpb.NewHealthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{}); err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("unary: %v, %v", resp, err)
	}
	if _, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: "missing"}); status.Code(err) != codes.NotFound {
		t.Fatalf("trailers-only error: got %v, want NotFound", err)
	}
	stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{Service: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	if first, err := stream.Recv(); err != nil || first.GetStatus() != healthpb.HealthCheckResponse_SERVICE_UNKNOWN {
		t.Fatalf("stream first: %v, %v", first, err)
	}
	hs.SetServingStatus("svc", healthpb.HealthCheckResponse_SERVING)
	if second, err := stream.Recv(); err != nil || second.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("stream second: %v, %v", second, err)
	}
}
