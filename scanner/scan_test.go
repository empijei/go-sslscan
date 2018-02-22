package scanner

import (
	"crypto/tls"
	"log"
	"net"
	"testing"
)

func TestScanHost(t *testing.T) {
	l, err := fooserver()
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = l.Close() }()

	//Default golang tls listener configuration
	expected := []string{
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		/*TODO
		TLS_ECDHE_RSA_AES256_GCM_SHA384
		TLS_ECDHE_RSA_AES256_SHA
		TLS_AES256_GCM_SHA384
		TLS_AES256_SHA
		TLS_ECDHE_RSA_AES128_GCM_SHA256
		TLS_ECDHE_RSA_AES128_SHA
		TLS_AES128_GCM_SHA256
		TLS_AES128_SHA
		TLS_ECDHE_RSA_DES_CBC3_SHA
		TLS_DES_CBC3_SHA
		TLS_ECDHE_RSA_AES256_SHA
		TLS_AES256_SHA
		TLS_ECDHE_RSA_AES128_SHA
		TLS_AES128_SHA
		TLS_ECDHE_RSA_DES_CBC3_SHA
		TLS_DES_CBC3_SHA
		TLS_ECDHE_RSA_AES256_SHA
		TLS_AES256_SHA
		TLS_ECDHE_RSA_AES128_SHA
		TLS_AES128_SHA
		TLS_ECDHE_RSA_DES_CBC3_SHA
		TLS_DES_CBC3_SHA
		SSL_AES256_SHA
		SSL_AES128_SHA
		SSL_DES_CBC3_SHA
		*/
	}
	cs, err := ScanHost("localhost:8043")
	if err != nil {
		t.Error(err)
		return
	}
	for i, c := range cs {
		if expected[i] != c.Name {
			t.Errorf("ScanHost: expected <%s> in position %d but got <%s>", expected[i], i, c.Name)
		}
	}
}

func fooserver() (net.Listener, error) {
	// Simple static webserver:
	cer, err := tls.LoadX509KeyPair("data/test_server.crt", "data/test_server.key")
	if err != nil {
		log.Fatal(err)
	}
	l, err := tls.Listen("tcp", ":8043", &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionSSL30,
	})
	go func() {
		for {
			c, errr := l.Accept()
			if errr != nil {
				return
			}
			_, _ = c.Write([]byte("hello"))
			_ = c.Close()
		}
	}()
	return l, err
}
