package main


import (
	"os"
	"fmt"
	"net"
	"encoding/hex"
)

func checkError(err error){
	if  err != nil {
		fmt.Println("Error: %s", err.Error())
		os.Exit(1)
	}
}

func recvUDPMsg(conn *net.UDPConn){
	var buf [100]byte
	defer conn.Close()

	_, raddr, err := conn.ReadFromUDP(buf[0:])
	if err != nil {
		return
	}

	fmt.Println(hex.Dump(buf[0:]))

	//WriteToUDP
	//func (c *UDPConn) WriteToUDP(b []byte, addr *UDPAddr) (int, error)
	_, err = conn.WriteToUDP([]byte("todo"), raddr)
	checkError(err)
}

func main() {
	udp_addr, err := net.ResolveUDPAddr("udp", ":2000")
	checkError(err)
	for {
		conn, err := net.ListenUDP("udp", udp_addr)
		checkError(err)

		//go recvUDPMsg(conn)
		recvUDPMsg(conn)

	}
}
