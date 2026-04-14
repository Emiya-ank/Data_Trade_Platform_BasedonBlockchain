package main

import (
	"flag"
	"log"

	communication "offchaincommunication/src"
)

func main() {
	baseURL := flag.String("base-url", "http://localhost:8080", "seller server base URL")
	orderID := flag.String("order-id", "", "trade order ID")
	saveDir := flag.String("save-dir", "./downloads", "directory to store downloaded files")
	flag.Parse()

	if *orderID == "" {
		log.Fatal("order-id is required")
	}

	if err := communication.DownloadTrade(*baseURL, *orderID, *saveDir); err != nil {
		log.Fatal(err)
	}
}
