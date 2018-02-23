package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"github.com/empijei/go-sslscan/scanner"
)

func main() {
	cer, err := tls.LoadX509KeyPair("scanner/data/test_server.crt", "scanner/data/test_server.key")
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
	fmt.Println(scanner.ScanHost("localhost:8043"))
	fmt.Println(scanner.ScanHost("google.com:443"))

	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}
