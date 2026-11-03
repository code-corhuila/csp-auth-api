package mail

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type receivedMail struct {
	from, auth string
	to         []string
	data       string
	encrypted  bool
}

// fakeServer is an in-process SMTP server: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT, DATA and QUIT.
type fakeServer struct {
	listener net.Listener
	cert     tls.Certificate
	rootCAs  *x509.CertPool
	startTLS bool
	rejectTo bool
	silent   bool
	mu       sync.Mutex
	received []receivedMail
}

func newFakeServer(t *testing.T, startTLS bool) *fakeServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{listener: listener, startTLS: startTLS}
	s.cert, s.rootCAs = selfSignedCert(t)
	t.Cleanup(func() { _ = listener.Close() })
	return s
}

func (s *fakeServer) start() {
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
}

func (s *fakeServer) port() int { return s.listener.Addr().(*net.TCPAddr).Port }

func (s *fakeServer) mails() []receivedMail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]receivedMail(nil), s.received...)
}

func between(line string) string {
	return line[strings.Index(line, "<")+1 : strings.Index(line, ">")]
}

func (s *fakeServer) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if s.silent {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	var rw io.ReadWriter = conn
	reply := func(line string) { _, _ = io.WriteString(rw, line+"\r\n") }
	reader := bufio.NewReader(rw)
	current, encrypted := receivedMail{}, false
	reply("220 fake ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch verb := strings.ToUpper(strings.Fields(line + " x")[0]); {
		case verb == "EHLO":
			reply("250-fake")
			if s.startTLS && !encrypted {
				reply("250-STARTTLS")
			}
			reply("250-AUTH PLAIN")
			reply("250 8BITMIME")
		case verb == "STARTTLS" && s.startTLS:
			reply("220 go ahead")
			secured := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			rw, reader, encrypted = secured, bufio.NewReader(secured), true
		case verb == "AUTH":
			current.auth = line
			reply("235 ok")
		case verb == "MAIL":
			current.from = between(line)
			reply("250 ok")
		case verb == "RCPT" && s.rejectTo:
			reply("550 no such user")
		case verb == "RCPT":
			current.to = append(current.to, between(line))
			reply("250 ok")
		case verb == "DATA":
			reply("354 go")
			var data strings.Builder
			for {
				part, err := reader.ReadString('\n')
				if err != nil || part == ".\r\n" {
					break
				}
				data.WriteString(part)
			}
			current.data, current.encrypted = data.String(), encrypted
			s.mu.Lock()
			s.received = append(s.received, current)
			s.mu.Unlock()
			current = receivedMail{}
			reply("250 queued")
		case verb == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
