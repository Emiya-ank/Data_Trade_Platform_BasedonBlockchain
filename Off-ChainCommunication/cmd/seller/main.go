package main

import (
	"flag"
	"log"

	communication "offchaincommunication/src"
)

func main() {
	addr := flag.String("addr", ":8080", "server listen address")
	dataDir := flag.String("data-dir", "./data", "directory that stores trade files")
	flag.Parse()

	log.Printf("Seller HTTP server listening on %s using %s", *addr, *dataDir)
	log.Fatal(communication.RunSellerServer(*addr, *dataDir))
}
