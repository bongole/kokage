package main

import (
	"flag"
	"fmt"
	"github.com/bongole/gopcapreader"
	"github.com/miekg/pcap"
	"log"
	"net"
	"net/http"
)

type Conf struct {
	dev        string
	host       string
	forward_to string
}

var CONF Conf

type HttpRequests struct{}

func (h *HttpRequests) HandleStream(stream *gopcapreader.Stream) {
	br := stream.BufferedReader()
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		client := &http.Client{
			Transport: &http.Transport{
				Dial: func(network, addr string) (net.Conn, error) {
					return net.Dial("tcp", CONF.forward_to)
				},
			},
		}

		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		req.RequestURI = ""

		_, cerr := client.Do(req)
		if cerr != nil {
			log.Print(cerr)
		}
	}
}

func main() {
	flag.StringVar(&CONF.dev, "i", "eth0", "pcap interface")
	flag.StringVar(&CONF.forward_to, "f", "127.0.0.1:80", "forward to")
	flag.StringVar(&CONF.host, "h", "127.0.0.1", "host that serves httpd")
	flag.Parse()

	h, err := pcap.OpenLive(CONF.dev, 65535, false, 1000)
	if err != nil {
		log.Fatal("pcap.OpenLive: ", err)
	}

	filter := fmt.Sprintf("dst host %s and tcp dst port 80", CONF.host)
	fmt.Printf("Using pcap filter: \"%s\"\n", filter)

	if filtErr := h.SetFilter(filter); filtErr != nil {
		log.Fatal("Setfilter: ", filtErr)
	}

	multiplexer := gopcapreader.NewMultiplexer(&HttpRequests{})
	multiplexer.MultiplexPcap(h, 0)
}
