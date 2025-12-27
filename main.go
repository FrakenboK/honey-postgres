package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	SSLRequestCode        = 80877103
	AuthCleartextPassword = 3
)

var (
	useTLS  bool
	outFile string
	port    int

	outMu sync.Mutex
	outFd *os.File
)

func main() {
	flag.BoolVar(&useTLS, "tls", false, "enable TLS (self-signed cert)")
	flag.StringVar(&outFile, "o", "", "output file for captured credentials")
	flag.IntVar(&port, "port", 5432, "port to listen on")
	flag.Parse()

	if outFile != "" {
		var err error
		outFd, err = os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer outFd.Close()
	}

	var tlsCfg *tls.Config
	if useTLS {
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatal(err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("Postgres honey-postgrespot listening on %s (tls=%v)\n", addr, useTLS)

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
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	code := binary.BigEndian.Uint32(buf[4:])
	if code != SSLRequestCode {
		return
	}

	if tlsCfg != nil {
		conn.Write([]byte("S"))
		tlsConn := tls.Server(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	} else {
		conn.Write([]byte("N"))
	}

	user, db, err := readStartupMessage(conn)
	if err != nil {
		return
	}

	sendAuthCleartext(conn)

	password, err := readPasswordMessage(conn)
	if err != nil {
		return
	}

	logAttempt(conn.RemoteAddr().String(), user, db, password)
	sendError(conn, "password authentication failed")
}

func logAttempt(addr, user, db, pass string) {
	line := fmt.Sprintf(
		"%s from=%s user=%s db=%s password=%q\n",
		time.Now().Format(time.RFC3339),
		addr, user, db, pass,
	)

	log.Print("[ATTEMPT] " + line)

	if outFd != nil {
		outMu.Lock()
		outFd.WriteString(line)
		outMu.Unlock()
	}
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
