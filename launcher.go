package main

import (
	"crypto/tls"
	"golang.org/x/crypto/ocsp"
)

func main() {
	sha256 := tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	ocsp.CreateRequest()
}
