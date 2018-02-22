package scanner

import (
	"sort"

	"github.com/empijei/go-sslscan/scanner/tls_dirty"
)

type ProtVersion uint16

//go:generate stringer -type ProtVersion
const (
	SSL30 ProtVersion = tls_dirty.VersionSSL30
	TLS10 ProtVersion = tls_dirty.VersionTLS10
	TLS11 ProtVersion = tls_dirty.VersionTLS11
	TLS12 ProtVersion = tls_dirty.VersionTLS12
)

var AllCiphersMap = make(map[uint16]CipherSuite)
var AllCiphers CipherSuites

func init() {
	for _, c := range TLS_CipherSuites {
		AllCiphersMap[c.ID] = c
	}
	for _, c := range IANA_CipherSuites {
		AllCiphersMap[c.ID] = c
	}
	AllCiphers = make([]CipherSuite, len(AllCiphersMap))
	i := 0
	for _, c := range AllCiphersMap {
		AllCiphers[i] = c
		i++
	}
	sort.Sort(ByID(AllCiphers))
}

type CipherSuite struct {
	ID       uint16
	Name     string
	Protocol Protocol
	Kx       KeyExchange
	Au       Authentication
	Enc      Encryption
	Bits     int
	Mac      Mac
}

type ByID CipherSuites

func (b ByID) Len() int {
	return len(b)
}

func (b ByID) Less(i int, j int) bool {
	return b[i].ID < b[j].ID
}

func (b ByID) Swap(i int, j int) {
	b[i], b[j] = b[j], b[i]
}

type CipherSuites []CipherSuite

func (cs CipherSuites) IDsMap() CipherSuitesMap {
	toret := make(CipherSuitesMap)
	for _, c := range cs {
		toret[c.ID] = c
	}
	return toret
}

func (cs CipherSuites) IDs() []uint16 {
	toret := make([]uint16, len(cs))
	for i, c := range cs {
		toret[i] = c.ID
	}
	return toret
}

type CipherSuitesMap map[uint16]CipherSuite

func (csm CipherSuitesMap) Slice() []uint16 {
	var cs []uint16
	for c, _ := range csm {
		cs = append(cs, c)
	}
	return cs
}

//The following definitions are enums to classify ciphers

type Protocol int

//go:generate stringer -type=Protocol
const (
	PROT_SSL Protocol = iota
	PROT_TLS
)

type KeyExchange int

//go:generate stringer -type=KeyExchange
const (
	KX_DH KeyExchange = iota
	KX_DHE
	KX_ECCPWD
	KX_ECDH
	KX_ECDHE
	KX_FORTEZZA
	KX_KRB5
	KX_KRB5_EXPORT
	KX_NULL
	KX_PSK
	KX_RSA
	KX_RSA_EXPORT
	KX_RSA_EXPORT_1024
	KX_RSA_FIPS
	KX_SRP
	KX_VKO_GOST_R_34_10_2001
	KX_VKO_GOST_R_34_10_94
)

type Authentication int

//go:generate stringer -type=Authentication
const (
	AU_ANON Authentication = iota
	AU_DHE
	AU_DSS
	AU_ECCPWD
	AU_ECDSA
	AU_EXPORT
	AU_KEA
	AU_KRB5
	AU_KRB5_EXPORT
	AU_NULL
	AU_PSK
	AU_RSA
	AU_RSA_EXPORT
	AU_RSA_EXPORT_1024
	AU_RSA_FIPS
	AU_SHA
	AU_VKO_GOST_R_34_10_2001
	AU_VKO_GOST_R_34_10_94
)

type Encryption int

//go:generate stringer -type=Encryption
const (
	ENC_3DES_EDE_CBC Encryption = iota
	ENC_AES_128
	ENC_AES_128_CBC
	ENC_AES_128_CCM
	ENC_AES_128_CCM_8
	ENC_AES_128_GCM
	ENC_AES_256
	ENC_AES_256_CBC
	ENC_AES_256_CCM
	ENC_AES_256_GCM
	ENC_ARIA_128_CBC
	ENC_ARIA_128_GCM
	ENC_ARIA_256_CBC
	ENC_ARIA_256_GCM
	ENC_CAMELLIA_128_CBC
	ENC_CAMELLIA_128_GCM
	ENC_CAMELLIA_256_CBC
	ENC_CAMELLIA_256_GCM
	ENC_CHACHA20_POLY1305
	ENC_CHACHA20_POLY1305_256
	ENC_DES40_CBC
	ENC_DES_CBC
	ENC_DES_CBC_40
	ENC_FORTEZZA_CBC
	ENC_GOST28147
	ENC_IDEA_CBC
	ENC_NULL
	ENC_RC2_CBC_40
	ENC_RC2_CBC_56
	ENC_RC4_128
	ENC_RC4_40
	ENC_RC4_56
	ENC_SEED_CBC
)

type Mac int

//go:generate stringer -type=Mac
const (
	MAC_GOST28147 Mac = iota
	MAC_GOSTR3411
	MAC_MD5
	MAC_NULL
	MAC_SHA
	MAC_SHA256
	MAC_SHA384
)
