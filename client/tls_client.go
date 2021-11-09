package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	for i := 0; i < 5; i++ {
		dial, err := net.Dial("tcp", "0.0.0.0:10080")
		if err != nil {
			log.Fatalf("got error while connecting to tcp server: %+v", err)
		}
		message := fmt.Sprintf("Hello: %d", i)
		_, err = dial.Write([]byte(message))
		if err != nil {
			log.Fatalf("got error while writing to tcp server: %+v", err)
		}
		time.Sleep(time.Second * 2)

		err = dial.Close()
		if err != nil {
			log.Printf("got error while closing connection to tcp server: %+v", err)
		}
	}
	//certificate := tls.Certificate{}
	//certificate.
}

func openTls() {
	tls.Dial("tcp", "", &tls.Config{})
}
