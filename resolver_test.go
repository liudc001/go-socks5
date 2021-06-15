package socks5

import (
	"fmt"
	"testing"

	"golang.org/x/net/context"
)

func TestDNSResolver(t *testing.T) {
	d := DNSResolver{}
	ctx := context.Background()

	_, addr, err := d.Resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !addr.IsLoopback() {
		t.Fatalf("expected loopback")
	}
}

func TestDNSResolver2(t *testing.T) {

	d := DNSResolver{}
	ctx := context.Background()
	dnsName := "www.baidu.com"

	_, addr, err := d.Resolve(ctx, dnsName)

	if err != nil {
		t.Fatal("域名解析报错")
	}

	fmt.Printf("域名[%s]\n", dnsName)
	fmt.Printf("解析ip为%s\n", addr.String())

}
