package responder

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

type Config struct {
	Ca            CAConfig      `yaml:"ca_config"`
	Responder     Responder     `yaml:"responder"`
	IndexFilePath string        `yaml:"index_file_path"`
	CertPath      string        `yaml:"cert_path"`
	CertType      string        `yaml:"cert_type"`
	KeyBits       int           `yaml:"key_bits"`
	Clients       []ClientEntry `yaml:"clients"`
}

type Responder struct {
	Port        int    `yaml:"port"`
	PrivateKey  string `yaml:"private_key"`
	CertFile    string `yaml:"cert_file"`
	CaCert      string `yaml:"ca_cert"`
	LogFile     string `yaml:"log_file"`
	LogToStdout bool   `yaml:"log_to_stdout"`
	Strict      bool   `yaml:"strict"`
	Address     string `yaml:"address"`
	Ssl         bool   `yaml:"ssl"`
}

type CAConfig struct {
	Organization  string `yaml:"organization"`
	Country       string `yaml:"country"`
	Province      string `yaml:"province"`
	Locality      string `yaml:"locality"`
	StreetAddress string `yaml:"street_address"`
	PostalCode    string `yaml:"postal_code"`
}

type ClientEntry struct {
	Dns      string `yaml:"dns"`
	Ip       string `yaml:"ip"`
	CertPath string `yaml:"cert_path"`
}

func createFile(name string) (*os.File, error) {
	return os.Create(name)
}

// parses a pem encoded x509 certificate
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

// parses a PEM encoded PKCS8 private key (RSA only)
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
