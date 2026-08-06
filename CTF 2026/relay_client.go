// relay_client is a minimal, standalone client stub for the "Relay Cipher"
// field-relay service. It is a DOWNLOADABLE participant artifact and is
// deliberately FLAG-FREE: it demonstrates exactly one handshake frame so you
// can observe the wire format, then prints whatever the server sends back.
//
// It is intentionally self-contained (no shared package) and the frame checksum
// algorithm is left unimplemented (the one byte below is a captured constant).
//
// Build:  go build -o relay_client relay_client.go
// Run:    ./relay_client <host> <port>      (default 127.0.0.1 9004)
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

// helloFrame is one captured, valid HELLO handshake frame. The service accepts
// it as-is. Study the field layout:
//
//	52 45 4C 59   magic     (4 bytes, constant "RELY")
//	01            opcode    (1 byte, 0x01 = HELLO)
//	00 00         length    (2 bytes, big-endian payload length = 0)
//	A6            checksum  (1 byte)
//	              payload   (0 bytes here)
//
// The server replies with its own framed message using the same layout.
var helloFrame = []byte{
	0x52, 0x45, 0x4C, 0x59, // magic "RELY"
	0x01,       // opcode: HELLO
	0x00, 0x00, // length: 0
	0xA6, // checksum
}

func main() {
	host := "127.0.0.1"
	port := "9004"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("-> sending HELLO handshake frame (%d bytes):\n%s\n",
		len(helloFrame), hex.Dump(helloFrame))

	if _, err := conn.Write(helloFrame); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("<- server replied (%d bytes):\n%s\n", n, hex.Dump(resp[:n]))
}
