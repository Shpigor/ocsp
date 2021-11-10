package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"
)

var useTls bool
var address string
var caCertPath string
var certPath string
var keyPath string
var certPool *x509.CertPool

func init() {
	flag.BoolVar(&useTls, "t", true, "use TLS connection.")
	flag.StringVar(&address, "a", "0.0.0.0:8080", "connection address to the nginx.")
	flag.StringVar(&caCertPath, "ca", "/Users/shpigor/ca/ca-cert.crt", "path to ca certificate file.")
	flag.StringVar(&certPath, "c", "/Users/shpigor/ca/client.crt", "path to certificate file.")
	flag.StringVar(&keyPath, "k", "/Users/shpigor/ca/client.pk", "path to private key file.")
	flag.Parse()
	certPool = x509.NewCertPool()
	certFile, err := parseCertFile(caCertPath)
	if err != nil {
		log.Fatalf("can't parse ca certificate file.")
	}
	certPool.AddCert(certFile)
}

func main() {
	for i := 0; i < 5; i++ {
		conn, err := openConnection()
		if err != nil {
			log.Fatalf("got error while connecting to tcp server: %+v", err)
		}
		message := fmt.Sprintf("Hello: %d", i)
		_, err = conn.Write([]byte(message))
		if err != nil {
			log.Fatalf("got error while writing to tcp server: %+v", err)
		}
		time.Sleep(time.Second * 2)

		err = conn.Close()
		if err != nil {
			log.Printf("got error while closing connection to tcp server: %+v", err)
		}
	}
}

func openConnection() (net.Conn, error) {
	if useTls {
		cert, err := parseCertFile(certPath)
		if err != nil {
			log.Fatalf("got error while parsing certificate: %+v", err)
		}
		pk, err := parseKeyFile(keyPath)
		if err != nil {
			log.Fatalf("got error while parsing private key: %+v", err)
		}
		return tls.Dial("tcp", address, &tls.Config{
			Certificates: []tls.Certificate{
				{
					PrivateKey:  pk,
					Certificate: [][]byte{cert.Raw},
				},
			},
			RootCAs: certPool,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				log.Println("Verifying peer certificate")
				return nil
			},
		})
	} else {
		return net.Dial("tcp", address)
	}
}

func parseCertFile(filename string) (*x509.Certificate, error) {
	ct, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(ct)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func parseKeyFile(filename string) (interface{}, error) {
	kt, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(kt)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
