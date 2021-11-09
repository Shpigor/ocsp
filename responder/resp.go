package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

type OCSPResponder struct {
	IndexFile    string
	RespKeyFile  string
	RespCertFile string
	CaCertFile   string
	LogFile      string
	LogToStdout  bool
	Strict       bool
	Port         int
	Address      string
	Ssl          bool
	IndexEntries []IndexEntry
	IndexModTime time.Time
	CaCert       *x509.Certificate
	RespCert     *x509.Certificate
	NonceList    [][]byte
}

func Responder() *OCSPResponder {
	return &OCSPResponder{
		IndexFile:    "index.txt",
		RespKeyFile:  "responder.key",
		RespCertFile: "responder.crt",
		CaCertFile:   "ca.crt",
		LogFile:      "/var/log/gocsp-responder.log",
		LogToStdout:  false,
		Strict:       false,
		Port:         8888,
		Address:      "",
		Ssl:          false,
		IndexEntries: nil,
		IndexModTime: time.Time{},
		CaCert:       nil,
		RespCert:     nil,
		NonceList:    nil,
	}
}

func (self *OCSPResponder) makeHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Print(fmt.Sprintf("Got %s request from %s", r.Method, r.RemoteAddr))
		if self.Strict && r.Header.Get("Content-Type") != "application/ocsp-request" {
			log.Println("Strict mode requires correct Content-Type header")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		b := new(bytes.Buffer)
		switch r.Method {
		case "POST":
			b.ReadFrom(r.Body)
		case "GET":
			log.Println(r.URL.Path)
			gd, err := base64.StdEncoding.DecodeString(r.URL.Path[1:])
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r := bytes.NewReader(gd)
			b.ReadFrom(r)
		default:
			log.Println("Unsupported request method")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// parse request, verify, create response
		w.Header().Set("Content-Type", "application/ocsp-response")
		resp, err := self.verify(b.Bytes())
		if err != nil {
			log.Print(err)
			// technically we should return an ocsp error response. but this is probably fine
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Print("Writing response")
		w.Write(resp)
	}
}

// I only know of two types, but more can be added later
const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
	StatusExpired = 'E'
)

type IndexEntry struct {
	Status byte
	Serial *big.Int // wow I totally called it
	// revocation reason may need to be added
	IssueTime         time.Time
	RevocationTime    time.Time
	DistinguishedName string
}

// function to parse the index file
func (self *OCSPResponder) parseIndex() error {
	var t string = "060102150405Z"
	finfo, err := os.Stat(self.IndexFile)
	if err == nil {
		// if the file modtime has changed, then reload the index file
		if finfo.ModTime().After(self.IndexModTime) {
			log.Print("Index has changed. Updating")
			self.IndexModTime = finfo.ModTime()
			// clear index entries
			self.IndexEntries = self.IndexEntries[:0]
		} else {
			// the index has not changed. just return
			return nil
		}
	} else {
		return err
	}

	// open and parse the index file
	if file, err := os.Open(self.IndexFile); err == nil {
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			var ie IndexEntry
			ln := strings.Fields(s.Text())
			ie.Status = []byte(ln[0])[0]
			ie.IssueTime, _ = time.Parse(t, ln[1])
			if ie.Status == StatusValid {
				ie.Serial, _ = new(big.Int).SetString(ln[2], 16)
				ie.DistinguishedName = ln[4]
				ie.RevocationTime = time.Time{} //doesn't matter
			} else if ie.Status == StatusRevoked {
				ie.Serial, _ = new(big.Int).SetString(ln[3], 16)
				ie.DistinguishedName = ln[5]
				ie.RevocationTime, _ = time.Parse(t, ln[2])
			} else {
				// invalid status or bad line. just carry on
				continue
			}
			self.IndexEntries = append(self.IndexEntries, ie)
		}
	} else {
		return err
	}
	return nil
}

// updates the index if necessary and then searches for the given index in the
// index list
func (self *OCSPResponder) getIndexEntry(s *big.Int) (*IndexEntry, error) {
	log.Println(fmt.Sprintf("Looking for serial 0x%x", s))
	if err := self.parseIndex(); err != nil {
		return nil, err
	}
	for _, ent := range self.IndexEntries {
		if ent.Serial.Cmp(s) == 0 {
			return &ent, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("Serial 0x%x not found", s))
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
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// takes a list of extensions and returns the nonce extension if it is present
func checkForNonceExtension(exts []pkix.Extension) *pkix.Extension {
	nonce_oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	for _, ext := range exts {
		if ext.Id.Equal(nonce_oid) {
			log.Println("Detected nonce extension")
			return &ext
		}
	}
	return nil
}

func (self *OCSPResponder) verifyIssuer(req *ocsp.Request) error {
	h := req.HashAlgorithm.New()
	h.Write(self.CaCert.RawSubject)
	if bytes.Compare(h.Sum(nil), req.IssuerNameHash) != 0 {
		return errors.New("Issuer name does not match")
	}
	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(self.CaCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return err
	}
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	if bytes.Compare(h.Sum(nil), req.IssuerKeyHash) != 0 {
		return errors.New("Issuer key hash does not match")
	}
	return nil
}

// takes the der encoded ocsp request, verifies it, and creates a response
func (self *OCSPResponder) verify(rawReq []byte) ([]byte, error) {
	var status int
	var revokedAt time.Time

	// parse the request
	req, err := ocsp.ParseRequest(rawReq)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	//make sure the request is valid
	if err := self.verifyIssuer(req); err != nil {
		log.Println(err)
		return nil, err
	}

	// get the index entry, if it exists
	ent, err := self.getIndexEntry(req.SerialNumber)
	if err != nil {
		log.Println(err)
		status = ocsp.Unknown
	} else {
		log.Print(fmt.Sprintf("Found entry %+v", ent))
		if ent.Status == StatusRevoked {
			log.Print("This certificate is revoked")
			status = ocsp.Revoked
			revokedAt = ent.RevocationTime
		} else if ent.Status == StatusValid {
			log.Print("This certificate is valid")
			status = ocsp.Good
		}
	}

	// parse key file
	// perhaps I should zero this out after use
	keyi, err := parseKeyFile(self.RespKeyFile)
	if err != nil {
		return nil, err
	}
	key, ok := keyi.(crypto.Signer)
	if !ok {
		return nil, errors.New("Could not make key a signer")
	}

	// check for nonce extension
	var responseExtensions []pkix.Extension
	nonce := checkForNonceExtension(exts)

	// check if the nonce has been used before
	if self.NonceList == nil {
		self.NonceList = make([][]byte, 10)
	}

	if nonce != nil {
		for _, n := range self.NonceList {
			if bytes.Compare(n, nonce.Value) == 0 {
				return nil, errors.New("This nonce has already been used")
			}
		}

		self.NonceList = append(self.NonceList, nonce.Value)
		responseExtensions = append(responseExtensions, *nonce)
	}

	// construct response template
	rtemplate := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      self.RespCert,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
		Extensions: exts,
	}

	// make a response to return
	resp, err := ocsp.CreateResponse(self.CaCert, self.RespCert, rtemplate, key)
	if err != nil {
		return nil, err
	}

	return resp, err
}

// setup an ocsp server instance with configured values
func (self *OCSPResponder) Serve() error {
	// setup logging
	if !self.LogToStdout {
		lf, err := os.OpenFile(self.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
		if err != nil {
			log.Fatal("Could not open log file " + self.LogFile)
		}
		defer lf.Close()
		log.SetOutput(lf)
	}

	//the certs should not change, so lets keep them in memory
	cacert, err := parseCertFile(self.CaCertFile)
	if err != nil {
		log.Fatal(err)
		return err
	}
	respcert, err := parseCertFile(self.RespCertFile)
	if err != nil {
		log.Fatal(err)
		return err
	}

	self.CaCert = cacert
	self.RespCert = respcert

	// get handler and serve
	handler := self.makeHandler()
	http.HandleFunc("/", handler)
	listenOn := fmt.Sprintf("%s:%d", self.Address, self.Port)
	log.Println(fmt.Sprintf("GOCSP-Responder starting on %s with SSL:%t", listenOn, self.Ssl))

	if self.Ssl {
		http.ListenAndServeTLS(listenOn, self.RespCertFile, self.RespKeyFile, nil)
	} else {
		http.ListenAndServe(listenOn, nil)
	}
	return nil
}
