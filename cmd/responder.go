package main

import (
	"log"
	responder "ocsp"
)

func main() {
	im, err := responder.InitIndexManager(config.IndexFilePath)
	if err != nil {
		log.Fatalf("caan't init index manager")
	}
	resp := &responder.OCSPResponder{
		Im:           im,
		RespKeyFile:  config.Responder.PrivateKey,
		RespCertFile: config.Responder.CertFile,
		CaCertFile:   config.Responder.CaCert,
		LogFile:      config.Responder.LogFile,
		LogToStdout:  config.Responder.LogToStdout,
		Strict:       config.Responder.Strict,
		Port:         config.Responder.Port,
		Address:      config.Responder.Address,
		Ssl:          config.Responder.Ssl,
	}
	err = resp.Serve()
	if err != nil {
		log.Printf("got error while starting OCSP responder: %+v", err)
	}
}
