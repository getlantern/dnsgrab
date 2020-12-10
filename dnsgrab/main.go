package main

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/getlantern/dnsgrab"
)

func main() {
	s, err := dnsgrab.Listen(2, ":55899", "8.8.8.8:53")
	if err != nil {
		fmt.Println(err)
		return
	}

	go debugQueries(s)
	s.Serve()
}

func debugQueries(s dnsgrab.Server) {
	for {
		time.Sleep(1 * time.Second)
		ip := make([]byte, 4)
		for id := uint32(1); id < 100000; id++ {
			binary.BigEndian.PutUint32(ip, id)
			name, ok := s.ReverseLookup(ip)
			if !ok {
				break
			}
			fmt.Printf("%d -> %v\n", id, name)
		}
	}
}
