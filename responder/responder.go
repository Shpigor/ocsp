package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	rnd "math/rand"
	"net"
	"os"
	"time"
)

const defaultPath = "/home/igor"
const caCertPrefix = "ca-cert"
const caKeyPrefix = "ca-key"
const crtFileExt = ".crt"
const pkFileExt = ".pk"

const defaultPkBits = 2048

var certName = pkix.Name{
	Organization:  []string{"Corinex, INC."},
	Country:       []string{"CA"},
	Province:      []string{"BC"},
	Locality:      []string{"Vancouver"},
	StreetAddress: []string{""},
	PostalCode:    []string{""},
}

var config = KeyConfig{
	KeyBits:  defaultPkBits,
	FilePath: defaultPath,
	Clients: []ClientEntry{
		{
			Dns: "client",
			Ip:  "10.0.0.1",
		},
		{
			Dns: "server",
			Ip:  "10.0.0.1",
		},
	},
}

var certPool *x509.CertPool
var caPrivateKey *rsa.PrivateKey
var caCert *x509.Certificate

func init() {
	certPool = x509.NewCertPool()
}
func main() {
	generateCACertAndKey()

	for _, entry := range config.Clients {
		err, _, _ := genAndSignCert(entry.Dns, []net.IP{net.ParseIP(entry.Ip)}, caPrivateKey, caCert)
		if err != nil {
			log.Printf("got error while generating cert: %+v", err)
		}
	}
}

func generateCACertAndKey() (*bytes.Buffer, *bytes.Buffer) {
	var err error
	caCert = &x509.Certificate{
		SerialNumber:          big.NewInt(rnd.Int63n(1000000)),
		Subject:               certName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err = rsa.GenerateKey(rand.Reader, defaultPkBits)
	if err != nil {
		log.Fatalf("got error while generating CA private key: %+v", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("got error while generating CA certificate: %+v", err)
	}

	err, caCertPEM := storeCertToFile(defaultPath, caCertPrefix, caBytes)
	if err != nil {
		log.Fatalf("got error while encoding CA certificate: %+v", err)
		return nil, nil
	}
	certPool.AppendCertsFromPEM(caCertPEM.Bytes())

	err, caPrivateKeyPEM := storePkToFile(defaultPath, caKeyPrefix, caPrivateKey)
	if err != nil {
		log.Fatalf("got error while encoding CA private key: %+v", err)
		return nil, nil
	}
	return caCertPEM, caPrivateKeyPEM
}

func genAndSignCert(dns string, ips []net.IP, caPrivateKey *rsa.PrivateKey, caCert *x509.Certificate) (error, *bytes.Buffer, *bytes.Buffer) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(rnd.Int63n(1000000)),
		Subject:      certName,
		IPAddresses:  ips,
		DNSNames:     []string{dns},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, defaultPkBits)
	if err != nil {
		return err, nil, nil
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return err, nil, nil
	}

	err, certPEM := storeCertToFile(defaultPath, dns, certBytes)
	if err != nil {
		return err, nil, nil
	}
	err, certPrivateKeyPEM := storePkToFile(defaultPath, dns, certPrivateKey)
	if err != nil {
		return err, nil, nil
	}
	return nil, certPEM, certPrivateKeyPEM
}

func storeCertToFile(path, prefix string, data []byte) (error, *bytes.Buffer) {
	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: data,
	})
	if err != nil {
		return err, nil
	}

	file, err := createFile(path + "/" + prefix + crtFileExt)
	if err != nil {
		return err, nil
	}
	_, err = file.Write(certPEM.Bytes())
	if err != nil {
		return err, nil
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("got error while close the file: %v", err)
		}
	}(file)
	return nil, certPEM
}

func storePkToFile(path, prefix string, key *rsa.PrivateKey) (error, *bytes.Buffer) {
	certPrivateKeyPEM := new(bytes.Buffer)
	err := pem.Encode(certPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return err, nil
	}
	file, err := createFile(path + "/" + prefix + pkFileExt)
	if err != nil {
		return err, nil
	}
	_, err = file.Write(certPrivateKeyPEM.Bytes())
	if err != nil {
		return err, nil
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("got error while close the file: %v", err)
		}
	}(file)
	return nil, certPrivateKeyPEM
}

func createFile(name string) (*os.File, error) {
	return os.Create(name)
}
