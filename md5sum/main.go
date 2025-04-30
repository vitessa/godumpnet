package main

import (
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

var (
	host    string
	port    string
	network string
)

func init() {
	network = "tcp"
	host = "127.0.0.1"

	flag.StringVar(&port, "p", "8000", "tcp port")
	flag.Parse()
}

func server(address string, wait chan<- string) {
	if addr, err := net.ResolveTCPAddr(network, address); err != nil {
		log.Fatal(err)
	} else if listener, err := net.ListenTCP(addr.Network(), addr); err != nil {
		log.Fatal(err)
	} else {
		log.Println("start listen", address)
		if conn, err := listener.AcceptTCP(); err != nil {
			log.Fatal(err)
		} else if conn.CloseWrite() != nil {
			log.Fatal(err)
		} else {
			md5 := md5.New()
			io.Copy(md5, conn)
			conn.Close()
			listener.Close()
			wait <- fmt.Sprintf("%x", md5.Sum(nil))
			close(wait)
		}
	}
}

func main() {
	address := fmt.Sprintf("%s:%s", host, port)
	wait := make(chan string, 1)

	go server(address, wait)

	filename := flag.Arg(0)
	if file, err := os.OpenFile(filename, os.O_RDONLY, 0644); err != nil {
		log.Fatal(err)
	} else if conn, err := net.Dial(network, address); err != nil {
		log.Fatal(err)
	} else {
		buf := make([]byte, 65536)
		for {
			if n, err := file.Read(buf); err != nil {
				break
			} else {
				conn.Write([]byte(fmt.Sprintf("%x", buf[:n])))
				<-time.After(10 * time.Millisecond)
			}
		}
		conn.Close()
	}

	if md5, ok := <-wait; ok {
		log.Println(md5, filename)
	}
}
