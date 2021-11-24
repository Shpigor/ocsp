package responder

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

const indexFileDateFormat = "060201150405Z"

type IndexManager struct {
	filePath     string
	indexFile    *os.File
	IndexEntries []IndexEntry
	IndexModTime time.Time
}

type IndexEntry struct {
	Status byte
	Serial *big.Int // wow I totally called it
	// revocation reason may need to be added
	IssueTime         time.Time
	RevocationTime    time.Time
	DistinguishedName string
}

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
	line := fmt.Sprintf("V\t%s\t\t%X\t%s\t%s\n", cert.NotAfter.Format(indexFileDateFormat), cert.SerialNumber, certPath, cert.DNSNames)
	_, err := im.indexFile.WriteString(line)
	if err != nil {
		log.Printf("got error while storing data to the index file: %+v", err)
	}
}

// function to parse the index file
func (im *IndexManager) parseIndex() error {
	finfo, err := im.indexFile.Stat()
	if err == nil {
		// if the file modtime has changed, then reload the index file
		if finfo.ModTime().After(im.IndexModTime) {
			log.Print("Index has changed. Updating")
			im.IndexModTime = finfo.ModTime()
			// clear index entries
			im.IndexEntries = im.IndexEntries[:0]
		} else {
			// the index has not changed. just return
			return nil
		}
	} else {
		return err
	}

	// open and parse the index file
	s := bufio.NewScanner(im.indexFile)
	for s.Scan() {
		var ie IndexEntry
		ln := strings.Fields(s.Text())
		ie.Status = []byte(ln[0])[0]
		ie.IssueTime, _ = time.Parse(indexFileDateFormat, ln[1])
		if ie.Status == StatusValid {
			ie.Serial, _ = new(big.Int).SetString(ln[2], 16)
			ie.DistinguishedName = ln[4]
			ie.RevocationTime = time.Time{} //doesn't matter
		} else if ie.Status == StatusRevoked {
			ie.Serial, _ = new(big.Int).SetString(ln[3], 16)
			ie.DistinguishedName = ln[5]
			ie.RevocationTime, _ = time.Parse(indexFileDateFormat, ln[2])
		} else {
			// invalid status or bad line. just carry on
			continue
		}
		im.IndexEntries = append(im.IndexEntries, ie)
	}
	return nil
}

// updates the index if necessary and then searches for the given index in the
// index list
func (im *IndexManager) getIndexEntry(s *big.Int) (*IndexEntry, error) {
	log.Println(fmt.Sprintf("Looking for serial 0x%x", s))
	if err := im.parseIndex(); err != nil {
		return nil, err
	}
	for _, ent := range im.IndexEntries {
		if ent.Serial.Cmp(s) == 0 {
			return &ent, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Serial 0x%x not found", s))
}
