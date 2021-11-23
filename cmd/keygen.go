package main

import (
	"flag"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"net"
	responder "ocsp"
	"path/filepath"
)

func loadKeyGenConfig(keyGenConfig interface{}) {
	configPath := flag.String("c", "./cmd/config.yaml", "config file path")
	flag.Parse()
	absConfigPath, err := filepath.Abs(*configPath)
	if err != nil {
		log.Fatalf("can't load absolute file path: %+v", err)
	}

	file, err := ioutil.ReadFile(absConfigPath)
	if err != nil {
		log.Fatalf("can't load configuration file: %+v", err)
	}
	err = yaml.Unmarshal(file, keyGenConfig)
	if err != nil {
		log.Fatalf("can't load yaml file: %+v", err)
	}
}

func main() {
	keyGenConfig := &responder.Config{}
	loadKeyGenConfig(keyGenConfig)
	manager := responder.NewCertManager(keyGenConfig)
	manager.GenerateCACertAndKey()
	for _, entry := range keyGenConfig.Clients {
		err, _, _ := manager.GenAndSignCert(entry.CertPath, entry.Dns, []net.IP{net.ParseIP(entry.Ip)})
		if err != nil {
			log.Printf("got error while generating cert: %+v", err)
		}
	}
}
