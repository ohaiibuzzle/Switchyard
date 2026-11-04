package core

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

type dialFunc func(addr string) (net.Conn, error)

var netDialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

func directDial(addr string) (net.Conn, error) { return netDialer.Dial("tcp", addr) }

func newDialer(raw string) (dialFunc, error) {
	if raw == "" {
		return directDial, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			p, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: p}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, netDialer)
		if err != nil {
			return nil, err
		}
		return func(a string) (net.Conn, error) { return d.Dial("tcp", a) }, nil
	case "http":
		return func(a string) (net.Conn, error) { return httpConnect(u, a) }, nil
	}
	return nil, fmt.Errorf("proxy: unsupported scheme %q", u.Scheme)
}

func httpConnect(u *url.URL, addr string) (net.Conn, error) {
	c, err := netDialer.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: addr}, Host: addr, Header: http.Header{}}
	if u.User != nil {
		p, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+p)))
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		c.Close()
		return nil, fmt.Errorf("proxy CONNECT %s: %s", addr, resp.Status)
	}
	c.SetDeadline(time.Time{})
	if br.Buffered() > 0 { // server spoke first through the tunnel; don't lose those bytes
		return &bufConn{c, br}, nil
	}
	return c, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
