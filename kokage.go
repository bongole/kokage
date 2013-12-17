package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/miekg/pcap"
	"io"
	"net"
	"net/http"
    "sync"
    "time"
)

type BlockableReadWriter struct {
	readbuf bytes.Buffer
	io.Reader
    io.Writer
	c chan []byte
    closed bool
    mutex sync.RWMutex
}

func NewBlockableReadWriter() *BlockableReadWriter {
	rw := &BlockableReadWriter{}
	rw.c = make(chan []byte, 10)
    rw.closed = false
	return rw
}

func (self *BlockableReadWriter) Write(data []byte) (nr int, err error) {
    self.mutex.Lock()
    defer self.mutex.Unlock()

    if self.closed {
        return 0, io.EOF
    }

	self.c <- data
	nr = len(data)
	return
}

func (self *BlockableReadWriter) Read(b []byte) (nr int, err error) {
	if 0 == self.readbuf.Len() {
        buf, ok := <-self.c
        if ok {
            self.readbuf.Write(buf)
        } else {
            return 0, io.EOF
        }
	}

	return self.readbuf.Read(b)
}

func (self *BlockableReadWriter) Close() {
    self.mutex.Lock()
    defer self.mutex.Unlock()

    self.closed = true
	close(self.c)
}

func RequestParser(reader *bufio.Reader) {
    for {
        req, err := http.ReadRequest(reader)
        if err == nil {
            mydial := func(network, addr string) (net.Conn, error) {
                return net.Dial("tcp", "127.0.0.1:3000")
            }

            client := &http.Client{
                Transport: &http.Transport{
                    Dial: mydial,
                },
            }

            req.URL.Scheme = "http"
            req.URL.Host = req.Host
            req.RequestURI = ""

            fmt.Printf("%s\n", req.URL.String())
            client.Do(req)
        } else {
            fmt.Printf("err = %s\n", err)
            return
        }
    }
}

type ReaderMap struct {
    mutex sync.RWMutex
	reader_map map[uint64]*BlockableReadWriter
}

func (self *ReaderMap) Get(id uint64) (*BlockableReadWriter,bool) {
    self.mutex.RLock()
    defer self.mutex.RUnlock()

    rw, ok := self.reader_map[id]
    return rw, ok
}

func (self *ReaderMap) Set(id uint64, rw *BlockableReadWriter) {
    self.mutex.Lock()
    defer self.mutex.Unlock()

    if rw == nil {
        delete(self.reader_map, id)
    } else {
        self.reader_map[id] = rw
    }
}

func (self *ReaderMap) Size() int {
    return len(self.reader_map)
}


func NewReaderMap() *ReaderMap {
    r := new(ReaderMap)
    r.reader_map = make(map[uint64]*BlockableReadWriter)
    return r
}

func main() {
	h, err := pcap.OpenLive("en1", 65535, false, 1000)
	if err != nil {
		fmt.Println(err)
        return
	}

	h.SetFilter("tcp dst port 80")

	reader_map := NewReaderMap()

    go func(){
        for {
            fmt.Printf("map = %d\n", reader_map.Size())
            time.Sleep(1 * time.Second)
        }
    }()

	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			continue
		}

		pkt.Decode()
		ip := pkt.Headers[0].(*pcap.Iphdr)
		tcp := pkt.Headers[1].(*pcap.Tcphdr)
		id := (uint64(binary.BigEndian.Uint32(ip.SrcIp)) << 16) | uint64(tcp.SrcPort)

		if (tcp.Flags & pcap.TCP_FIN) != 0 {
			if rw, ok := reader_map.Get(id); ok {
				rw.Close()
                reader_map.Set(id, nil)
			}

			continue
		}

		if pkt.Payload != nil && 0 < len(pkt.Payload) {
			if _, ok := reader_map.Get(id); !ok {
                rw := NewBlockableReadWriter()

				reader_map.Set(id, rw)

				go RequestParser(bufio.NewReader(rw))
			}

			go func(id_ uint64, data []byte) {
                if rw, ok := reader_map.Get(id_); ok {
                    rw.Write(data)
                }
			}(id, pkt.Payload)
		}
	}
}
