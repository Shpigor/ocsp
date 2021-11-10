package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

const indexFileDateFormat = "060201150405Z"

func InitIndexManager(filePath string) (*IndexManager, error) {
	indexFile, err := os.OpenFile(filePath, os.O_RDWR, os.ModeAppend)
	if os.IsNotExist(err) {
		indexFile, err = os.Create(filePath)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return &IndexManager{
		filePath:  filePath,
		indexFile: indexFile,
	}, nil
}

type IndexManager struct {
	filePath  string
	indexFile *os.File
}

//1. Status flag (V for valid, R for revoked, E for expired)
//2. Expiration date (in YYMMDDHHMMSSZ format)
//3. Revocation date or empty if not revoked
//4. Serial number (hexadecimal)
//5. File location or unknown if not known
//6. Distinguished name
func (im *IndexManager) addCertToIndex(cert *x509.Certificate, filePath string) {
	certPath := filePath
	if len(certPath) <= 0 {
		certPath = "unknown"
	}
	line := fmt.Sprintf("V\t%s\t%X\t%s\t%s\n", cert.NotAfter.Format(indexFileDateFormat), cert.SerialNumber, certPath, cert.DNSNames)
	_, err := im.indexFile.WriteString(line)
	if err != nil {
		log.Printf("got error while storing data to the index file: %+v", err)
	}
}
