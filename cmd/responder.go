package main

import (
	"flag"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	responder "ocsp"
	"path/filepath"
)

func loadRespConfig(respConfig *responder.Config) {
	configPath := flag.String("c", "./cmd/config.yaml", "config file path")
	flag.Parse()
	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatalf("can't load absolute file path: %+v", err)
	}

	fileData, err := ioutil.ReadFile(absConfigPath)
	if err != nil {
		log.Fatalf("can't load configuration file: %+v", err)
	}
	err = yaml.Unmarshal(fileData, respConfig)
	if err != nil {
		log.Fatalf("can't load yaml file: %+v", err)
	}
}

func main() {
	respConfig := &responder.Config{}
	loadRespConfig(respConfig)
	im, err := responder.InitIndexManager(respConfig.IndexFilePath)
	if err != nil {
		log.Fatalf("caan't init index manager")
	}
	resp := &responder.OCSPResponder{
		Im:           im,
		RespKeyFile:  respConfig.Responder.PrivateKey,
		RespCertFile: respConfig.Responder.CertFile,
		CaCertFile:   respConfig.Responder.CaCert,
		LogFile:      respConfig.Responder.LogFile,
		LogToStdout:  respConfig.Responder.LogToStdout,
		Strict:       respConfig.Responder.Strict,
		Port:         respConfig.Responder.Port,
		Address:      respConfig.Responder.Address,
		Ssl:          respConfig.Responder.Ssl,
	}
	err = resp.Serve()
	if err != nil {
		log.Printf("got error while starting OCSP responder: %+v", err)
	}
}
