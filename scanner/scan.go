package scanner

import (
	"net"

	"github.com/empijei/cli/lg"
	"github.com/empijei/go-sslscan/scanner/tls_dirty"
)

func ScanHost(hostport string) ([]CipherSuite, error) {
	suites := TLS_CipherSuites.IDsMap()
	protocols := []ProtVersion{
		//FIXME this needs to be heandled separtely SSL30,
		TLS10,
		TLS11,
		TLS12,
	}

	var found []CipherSuite
	for _, p := range protocols {
		lg.Debugf("Now attempting with protocol: %s", p)
		for {
			c, err := tls_dirty.DialWithDialerNoHandShake(new(net.Dialer), "tcp", hostport, nil)
			if err != nil {
				return nil, err
			}
			c.SetMaxVersion(uint16(p))
			srvHello, err := c.TrySuites(suites.Slice())
			if err != nil {
				//we finished looking for suites, no common suites
				lg.Debug(err)
				break
			}
			if cs, ok := suites[srvHello.CipherSuite()]; ok {
				found = append(found, cs)
				lg.Debugf("Found cipher: %s", cs.Name)
				delete(suites, srvHello.CipherSuite())
			} else {
				//Unknown cipher????
				lg.Infof("Unknown ciphers: %X", srvHello.CipherSuite())
			}
		}
	}
	return found, nil
}

func ScanHostWithProto(hostport string, p ProtVersion) ([]CipherSuite, error) {
	suites := TLS_CipherSuites.IDsMap()
	var found []CipherSuite
	lg.Debugf("Now attempting with protocol: %s", p)
	for {
		c, err := tls_dirty.DialWithDialerNoHandShake(new(net.Dialer), "tcp", hostport, nil)
		if err != nil {
			return nil, err
		}
		c.SetMaxVersion(uint16(p))
		srvHello, err := c.TrySuites(suites.Slice())
		if err != nil {
			//we finished looking for suites, no common suites
			lg.Debug(err)
			break
		}
		if cs, ok := suites[srvHello.CipherSuite()]; ok {
			found = append(found, cs)
			lg.Debugf("Found cipher: %s", cs.Name)
			delete(suites, srvHello.CipherSuite())
		} else {
			//Unknown cipher????
			lg.Infof("Unknown ciphers: %X", srvHello.CipherSuite())
		}
	}
	return found, nil
}
