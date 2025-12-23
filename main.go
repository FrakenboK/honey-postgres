package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

const (
	SSLRequestCode        = 80877103
	AuthCleartextPassword = 3
)

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", ":5432")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Println("Postgres honeypot listening on :5432")

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn, tlsCfg)
	}
}

func handle(conn net.Conn, tlsCfg *tls.Config) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// === SSLRequest ===
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	code := binary.BigEndian.Uint32(buf[4:])
	if code != SSLRequestCode {
		return
	}

	// Say "yes, SSL"
	conn.Write([]byte("S"))

	// Upgrade to TLS
	tlsConn := tls.Server(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	user, db, err := readStartupMessage(tlsConn)
	if err != nil {
		return
	}

	sendAuthCleartext(tlsConn)

	password, err := readPasswordMessage(tlsConn)
	if err != nil {
		return
	}

	log.Printf(
		"[ATTEMPT] from=%s user=%s db=%s password=%q",
		conn.RemoteAddr(), user, db, password,
	)

	sendError(tlsConn, "password authentication failed")
}

func readStartupMessage(conn net.Conn) (user, db string, err error) {
	lenBuf := make([]byte, 4)
	if _, err = io.ReadFull(conn, lenBuf); err != nil {
		return
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)
	payload := make([]byte, msgLen-4)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return
	}

	parts := splitNull(payload[4:])
	for i := 0; i+1 < len(parts); i += 2 {
		switch parts[i] {
		case "user":
			user = parts[i+1]
		case "database":
			db = parts[i+1]
		}
	}
	return
}

func sendAuthCleartext(conn net.Conn) {
	buf := make([]byte, 9)
	buf[0] = 'R'
	binary.BigEndian.PutUint32(buf[1:], 8)
	binary.BigEndian.PutUint32(buf[5:], AuthCleartextPassword)
	conn.Write(buf)
}

func readPasswordMessage(conn net.Conn) (string, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", err
	}

	if hdr[0] != 'p' {
		return "", fmt.Errorf("unexpected message")
	}

	msgLen := binary.BigEndian.Uint32(hdr[1:])
	body := make([]byte, msgLen-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return "", err
	}

	return string(body[:len(body)-1]), nil
}

func sendError(conn net.Conn, msg string) {
	payload := fmt.Sprintf("SERROR\x00C28P01\x00M%s\x00\x00", msg)
	totalLen := 4 + len(payload)

	conn.Write([]byte{
		'E',
		byte(totalLen >> 24),
		byte(totalLen >> 16),
		byte(totalLen >> 8),
		byte(totalLen),
	})
	conn.Write([]byte(payload))
}

func splitNull(b []byte) []string {
	var res []string
	start := 0
	for i, c := range b {
		if c == 0 {
			res = append(res, string(b[start:i]))
			start = i + 1
		}
	}
	return res
}
