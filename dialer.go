package certexpire

import (
	"context"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

func TCPDailer(hostaddr string, proxyaddr *Proxy, timeout time.Duration) (net.Conn, error) {
	if proxyaddr == nil {
		return net.DialTimeout("tcp", hostaddr, timeout)
	}
	dial, err := proxy.SOCKS5("tcp", proxyaddr.Server, nil, nil)
	if err != nil {
		return nil, err
	}
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	d := dial.(proxy.ContextDialer)
	return d.DialContext(ctx, "tcp", hostaddr)
}
