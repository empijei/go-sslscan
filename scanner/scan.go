package scanner

import (
	"net"

	"github.com/empijei/go-sslscan/scanner/tls_dirty"
)

func ScanHost(hostport string) ([]CipherSuite, error) {
	suites := SSL3_TLS_CipherSuites.IDsMap()
	var found []CipherSuite
	for {
		c, err := tls_dirty.DialWithDialerNoHandShake(new(net.Dialer), "tcp", hostport, nil)
		if err != nil {
			return nil, err
		}
		srvHello, err := c.TrySuites(suites.Slice())
		if err != nil {
			//we finished looking for suites, no common suites
			break
		}
		if cs, ok := suites[srvHello.CipherSuite()]; ok {
			found = append(found, cs)
			delete(suites, srvHello.CipherSuite())
		} else {
			//Unknown cipher????
		}
	}
	return found, nil
}
