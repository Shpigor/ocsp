package responder

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const caCertPrefix = "ca-cert"
const caKeyPrefix = "ca-key"
const crtFileExt = ".crt"
const pkFileExt = ".pk"

const defaultPkBits = 2048

type CertManager struct {
	indexManager *IndexManager
	certPool     *x509.CertPool
	caCert       *x509.Certificate
	caPrivateKey *rsa.PrivateKey
	certName     pkix.Name
	certPath     string
}

func NewCertManager(config *Config) *CertManager {
	manager, err := InitIndexManager(config.IndexFilePath)
	if err != nil {
		log.Fatalf("got error while init index manager")
	}
	return &CertManager{
		indexManager: manager,
		certPool:     x509.NewCertPool(),
		certName: pkix.Name{
			Organization:  []string{config.Ca.Organization},
			Country:       []string{config.Ca.Country},
			Province:      []string{config.Ca.Province},
			Locality:      []string{config.Ca.Locality},
			StreetAddress: []string{config.Ca.StreetAddress},
			PostalCode:    []string{config.Ca.PostalCode},
		},
		certPath: config.CertPath,
	}
}

func (cm *CertManager) GenerateCACertAndKey() (*bytes.Buffer, *bytes.Buffer) {
	var err error
	cm.caCert = &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixMicro()),
		Subject:               cm.certName,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	cm.caPrivateKey, err = rsa.GenerateKey(rand.Reader, defaultPkBits)
	if err != nil {
		log.Fatalf("got error while generating CA private key: %+v", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, cm.caCert, cm.caCert, &cm.caPrivateKey.PublicKey, cm.caPrivateKey)
	if err != nil {
		log.Fatalf("got error while generating CA certificate: %+v", err)
	}

	err, caCertPEM := cm.storeCertToFile(cm.certPath, caCertPrefix, caBytes, cm.caCert)
	if err != nil {
		log.Fatalf("got error while encoding CA certificate: %+v", err)
		return nil, nil
	}
	cm.certPool.AppendCertsFromPEM(caCertPEM.Bytes())

	err, caPrivateKeyPEM := cm.storePkToFile(cm.certPath, caKeyPrefix, cm.caPrivateKey)
	if err != nil {
		log.Fatalf("got error while encoding CA private key: %+v", err)
		return nil, nil
	}
	return caCertPEM, caPrivateKeyPEM
}

func (cm *CertManager) GenAndSignCert(path, dns string, ips []net.IP) (error, *bytes.Buffer, *bytes.Buffer) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMicro()),
		Subject:      cm.certName,
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

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cm.caCert, &certPrivateKey.PublicKey, cm.caPrivateKey)
	if err != nil {
		return err, nil, nil
	}
	if len(path) == 0 {
		path = cm.certPath
	}
	err, certPEM := cm.storeCertToFile(path, dns, certBytes, cert)
	if err != nil {
		return err, nil, nil
	}
	err, certPrivateKeyPEM := cm.storePkToFile(path, dns, certPrivateKey)
	if err != nil {
		return err, nil, nil
	}
	return nil, certPEM, certPrivateKeyPEM
}

func (cm *CertManager) storeCertToFile(path, prefix string, data []byte, cert *x509.Certificate) (error, *bytes.Buffer) {
	certPEM := new(bytes.Buffer)
	err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: data,
	})
	if err != nil {
		return err, nil
	}

	fullFileName := path + "/" + prefix + crtFileExt
	file, err := createFile(fullFileName)
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
	cm.indexManager.addCertToIndex(cert, fullFileName)
	return nil, certPEM
}

func (cm *CertManager) storePkToFile(path, prefix string, key *rsa.PrivateKey) (error, *bytes.Buffer) {
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
