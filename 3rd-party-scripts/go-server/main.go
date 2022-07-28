package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	cert := flag.String("cert", "localhost.crt", "Server certificate in PEM format")
	key := flag.String("key", "localhost.key", "Server certificate's corresponding key, in PEM format")
	addr := flag.String("addr", ":443", "Server's listening address")

	flag.Parse()

	log.Printf("Running with cert: %v / key: %v", *cert, *key)

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("go-server@tlsfuzzer\n"))
		log.Println("Replied to request")
	})

	err := http.ListenAndServeTLS(*addr, *cert, *key, nil)
	if err != nil {
		log.Fatalf("Got error while serving (on %v): %v", *addr, err)
	}
}
