package main

import (
	"flag"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"net"
	responder "ocsp"
)

var configPath string
var config *responder.Config

func init() {
	flag.StringVar(&configPath, "c", "./config.yaml", "config file path")
	flag.Parse()
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("can't load configuration file: %+v", err)
	}
	err = yaml.Unmarshal(file, config)
	if err != nil {
		log.Fatalf("can't load yaml file: %+v", err)
	}
}

func main() {

	manager := responder.NewCertManager(config)
	manager.GenerateCACertAndKey()
	for _, entry := range config.Clients {
		err, _, _ := manager.GenAndSignCert(entry.CertPath, entry.Dns, []net.IP{net.ParseIP(entry.Ip)})
		if err != nil {
			log.Printf("got error while generating cert: %+v", err)
		}
	}
}
