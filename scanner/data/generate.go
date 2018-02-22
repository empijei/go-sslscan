package main

import (
	"encoding/csv"
	"os"
	"strconv"
	"strings"
	"text/template"
)

var Ciphers []Cipher

type Cipher struct {
	Bytes, Name, Prot, Kx, Au, Enc string
	Bits                           int
	Mac                            string
}

func ParseCipher(line []string) Cipher {
	line[1] = strings.ToUpper(line[1])
	b := line[0][2:4] + line[0][7:]
	n := line[1]
	ws := strings.Split(line[1], "WITH")
	us := strings.Split(ws[0], "_")
	us = us[:len(us)-1]
	p := us[0]
	k := us[1]
	a := ""
	if len(us) > 2 {
		a = us[2]
	} else {
		a = k
	}
	us = strings.Split(ws[1], "_")
	us = us[1:]
	m := us[len(us)-1]
	en := us[:len(us)-1]
	i := 0
	for _, s := range en {
		switch {
		case strings.Contains(s, "3DES"):
			i = 128
		case strings.Contains(s, "DES"):
			i = 40
		case strings.Contains(s, "CHACHA"):
			i = 256
		default:
			i, _ = strconv.Atoi(s)
		}
		if i != 0 {
			break
		}
	}
	e := strings.Join(en, "_")
	e = strings.Replace(e, "__", "_", -1)
	if m == "CCM" || m == "8" {
		m = "SHA256"
	}
	return Cipher{b, n, p, k, a, e, i, m}
}

const tmplstr = `package scanner

var IANA_CipherSuites = CipherSuites{ {{range .}}
	CipherSuite{0x{{.Bytes}}, "{{.Name}}", PROT_{{.Prot}}, KX_{{.Kx}}, AU_{{.Au}}, ENC_{{.Enc}}, {{.Bits}}, MAC_{{.Mac}}},{{ end }}
}`

func main() {
	f, err := os.Open("IANA_ciphers.txt")
	_panic(err)
	r := csv.NewReader(f)
	r.Comma = '\t'
	_, err = r.Read()
	_panic(err)
	for line, err := r.Read(); err == nil; line, err = r.Read() {
		if strings.Contains(line[1], "Reserved") ||
			strings.Contains(line[1], "Unassigned") ||
			strings.Contains(line[1], "_SCSV") {
			continue
		}
		Ciphers = append(Ciphers, ParseCipher(line))
	}
	t := template.Must(template.New("ciphers").Parse(tmplstr))
	err = t.Execute(os.Stdout, Ciphers)
	_panic(err)
}

func _panic(err error) {
	if err != nil {
		panic(err)
	}
}
