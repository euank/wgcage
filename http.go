package main

import (
	"io"
	"net"
)

// TeeReadCloser returns a Reader that writes to w what it reads from r,
// just like io.TeeReader, and also implements Close
func TeeReadCloser(r io.ReadCloser, w io.Writer) io.ReadCloser {
	return &teeReadCloser{r, w}
}

type teeReadCloser struct {
	r io.ReadCloser
	w io.Writer
}

func (t *teeReadCloser) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}

func (t *teeReadCloser) Close() error {
	return t.r.Close()
}

// CountBytesConn is a net.Conn that counts bytes read and written
type countBytesConn struct {
	net.Conn
	read, written int64
}

func (conn *countBytesConn) Read(b []byte) (int, error) {
	n, err := conn.Conn.Read(b)
	conn.read += int64(n)
	return n, err
}

func (conn *countBytesConn) Write(b []byte) (int, error) {
	n, err := conn.Conn.Write(b)
	conn.written += int64(n)
	return n, err
}

func ipFromAddr(addr net.Addr) net.IP {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		return addr.IP
	case *net.TCPAddr:
		return addr.IP
	default:
		return nil
	}
}
