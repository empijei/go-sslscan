package tls_dirty

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

var cleanCipherSuites []*cipherSuite

func init() {
	cleanCipherSuites = cipherSuites
}

//Taken from DialWithDialer
func DialWithDialerNoHandShake(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	// We want the Timeout and Deadline values from dialer to cover the
	// whole process: TCP connection and TLS handshake. This means that we
	// also need to start our own timers now.
	timeout := dialer.Timeout

	if !dialer.Deadline.IsZero() {
		deadlineTimeout := time.Until(dialer.Deadline)
		if timeout == 0 || deadlineTimeout < timeout {
			timeout = deadlineTimeout
		}
	}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	//empijei moved this out since the rest of the code is polluting conf
	// Make a copy to avoid polluting argument or default.
	c := config.Clone()
	config = c

	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		c.ServerName = hostname
	}

	conn := Client(rawConn, config)
	return conn, nil
}

func (c *Conn) CheckServerSuiteSupport(suiteId uint16) (bool, error) {
	sh, err := c.TrySuites([]uint16{suiteId})
	if err != nil {
		if strings.Contains(err.Error(), alertText[alertHandshakeFailure]) {
			err = nil
		}
		return false, err
	}
	return suiteId == sh.cipherSuite, nil
}

func (c *Conn) TrySuites(suitesId []uint16) (*ServerHelloMsg, error) {
	c.config.CipherSuites = suitesId
	ch := &ClientHelloMsg{
		vers:                         c.config.maxVersion(),
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(c.config.ServerName),
		supportedCurves:              c.config.curvePreferences(),
		supportedPoints:              []uint8{pointFormatUncompressed},
		nextProtoNeg:                 len(c.config.NextProtos) > 0,
		secureRenegotiationSupported: true,
		alpnProtocols:                c.config.NextProtos,
	}
	return c.GetServerHello(ch)
}

//Taken from cliendhandshake.
//Using this breaks both c and the general TLS tunnel, so it
//closes the connection as it is rendered unusable.
func (c *Conn) GetServerHello(clientHello *ClientHelloMsg) (*ServerHelloMsg, error) {
	defer c.Close()
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify {
		return nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	nextProtosLength := 0
	for _, proto := range c.config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, errors.New("tls: NextProtos values too large")
	}

	hello := clientHello

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	possibleCipherSuites := c.config.cipherSuites()
	hello.cipherSuites = make([]uint16, len(possibleCipherSuites))
	// empijei I don't want the suites check as it just selects some of the ciphers.
	// since I don't need to actually be able to communicate over the established
	// conn, I just want to keep EVERY cipher in the conf
	copy(hello.cipherSuites, possibleCipherSuites)

	_, err := io.ReadFull(c.config.rand(), hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	if hello.vers >= VersionTLS12 {
		hello.signatureAndHashes = supportedSignatureAlgorithms
	}

	//empijei removed never-to-be-used session resumption
	if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return nil, err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	serverHello, ok := msg.(*ServerHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(serverHello, msg)
	}
	return serverHello, nil
}

func (sh *ServerHelloMsg) CipherSuite() uint16 {
	return sh.cipherSuite
}
