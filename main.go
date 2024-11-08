package smartproxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type ProxyAuth struct {
	Login    string
	Password string
}
type Proxy struct {
	Addr string
	Port uint16
	Auth ProxyAuth
}

// StringToProxy - converts a string to a Proxy object.
// The string should be in one of the following formats:
//   - "host:port"
//   - "host:port:login:password"
//   - "login:password@host:port"
func StringToProxy(str string) Proxy {
	if strings.Contains(str, "@") {
		// Format "login:password@host:port"
		dt := strings.Split(str, "@")
		auth := stringToProxyAuth(dt[0])
		dta := strings.Split(dt[1], ":")
		host := dta[0]
		port, _ := strconv.ParseUint(dta[1], 10, 16)
		return Proxy{
			Addr: host,
			Port: uint16(port),
			Auth: auth,
		}
	} else {
		// Format "host:port"
		dt := strings.Split(str, ":")
		host := dt[0]
		port, _ := strconv.ParseUint(dt[1], 10, 16)
		if len(dt) == 2 {
			return Proxy{
				Addr: host,
				Port: uint16(port),
			}

		} else if len(dt) == 4 {
			login := dt[2]
			password := dt[3]
			return Proxy{
				Addr: host,
				Port: uint16(port),
				Auth: ProxyAuth{login, password},
			}
		}
	}

	return Proxy{}
}

func stringToProxyAuth(str string) ProxyAuth {
	dt := strings.Split(str, ":")
	login := dt[0]
	password := dt[1]
	return ProxyAuth{login, password}

}

func (p *Proxy) GetProxyUrl() *url.URL {
	var proxyUrl *url.URL
	if p.Auth.Login == "" && p.Auth.Password == "" {
		proxyUrl, _ = url.Parse("socks5://" + p.Addr + ":" + strconv.Itoa(int(p.Port)))
	} else {
		var err error
		proxyUrl, err = url.Parse("socks5://" + p.Auth.Login + ":" + p.Auth.Password + "@" + p.Addr + ":" + strconv.Itoa(int(p.Port)))
		if err != nil {
			fmt.Println(err)
		}
	}
	// fmt.Println("proxyUrl", proxyUrl)
	return proxyUrl
}

func (p *Proxy) CreateTcpDialer() (proxy.Dialer, error) {

	socks5 := p.Addr + ":" + fmt.Sprint(p)
	return proxy.SOCKS5("tcp", socks5, &proxy.Auth{
		User:     p.Auth.Login,
		Password: p.Auth.Password,
	}, &net.Dialer{
		Timeout:   60 * time.Second,
		KeepAlive: 30 * time.Second,
	})
}

func (p *Proxy) CreateTcpConn(target string) (net.Conn, error) {
	dialer, err := p.CreateTcpDialer()
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", target)
}
func (p *Proxy) CreateTlsConn(target string, tlsConfig *tls.Config) (*tls.Conn, error) {
	rawConn, err := p.CreateTcpConn(target)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	return tlsConn, nil

}
func (p *Proxy) CreateHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(p.GetProxyUrl()), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}
