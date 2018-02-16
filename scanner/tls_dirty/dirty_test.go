package tls_dirty

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestServerSuite(t *testing.T) {
	tests := []struct {
		insuites  []uint16
		requested uint16
		out       bool
	}{
		{[]uint16{TLS_RSA_WITH_RC4_128_SHA}, TLS_RSA_WITH_RC4_128_SHA, true},
		{[]uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_RC4_128_SHA}, TLS_RSA_WITH_RC4_128_SHA, true},
		{[]uint16{TLS_RSA_WITH_RC4_128_SHA}, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, false},
	}
	for i, tt := range tests {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		server.TLS = &tls.Config{
			CipherSuites: tt.insuites,
		}
		server.StartTLS()

		uri, _ := url.Parse(server.URL)
		c, err := DialWithDialerNoHandShake(new(net.Dialer), "tcp", uri.Host, nil)
		if err != nil {
			t.Error(err)
			server.Close()
			continue
		}
		s, err := c.CheckServerSuiteSupport(tt.requested)
		if err != nil {
			t.Error(err)
			server.Close()
			c.Close()
			continue
		}
		if s != tt.out {
			t.Errorf("test[%d] expected %v but got %v", i, tt.out, s)
		}
		server.Close()
		c.Close()
	}
}
