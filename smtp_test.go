package gold

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	tlsConfig = &tls.Config{
		NextProtos: []string{"http/1.1"},
	}
	tlsTestCert = []byte(`-----BEGIN CERTIFICATE-----
MIIB4TCCAUygAwIBAgIBADALBgkqhkiG9w0BAQUwEjEQMA4GA1UEChMHQWNtZSBD
bzAeFw0xNDAxMzAyMzUyMTlaFw0yNDAxMjgyMzUyMTlaMBIxEDAOBgNVBAoTB0Fj
bWUgQ28wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMs8NmXX55GqvTRcIE2K
8ZoElA7xRuiIYPXFl6Zlt/xCYUzcxEEz2pKOX3jgYEzx4wG0hQ5bcNQMJWPftZ7K
6QBvDRWs8wVgrbeN8o9LelPDrPl40Zk96howpgek/nPd5AUt6y0/hV4CNVt07y+D
13BxZSEj1E8ZTwCwhQ9uGltPAgMBAAGjSzBJMA4GA1UdDwEB/wQEAwIAoDATBgNV
HSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDALBgkqhkiG9w0BAQUDgYEAawZEY85RZAKrROH3t1xuGLI+MIWmiFH5Z/aQ
3kA/v5YHLlygjbgxedgFEe9TodiMk9M7kUTmAM6vS2qYf+apAj2QHFFyR8xc/BZ2
YHpBjeARoeg1ctbzCWeISB4BN7hOAQOojKcgaqbP49S5WG+ONfF6GuRE3oBJPJZf
1bRSET8=
-----END CERTIFICATE-----`)
	tlsTestKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDLPDZl1+eRqr00XCBNivGaBJQO8UboiGD1xZemZbf8QmFM3MRB
M9qSjl944GBM8eMBtIUOW3DUDCVj37WeyukAbw0VrPMFYK23jfKPS3pTw6z5eNGZ
PeoaMKYHpP5z3eQFLestP4VeAjVbdO8vg9dwcWUhI9RPGU8AsIUPbhpbTwIDAQAB
AoGAc00U25CzCvxf3V3K4dNLIIMqcJPIE9KTl7vjPn8E87PBOfchzJAbl/v4BD7f
w6eTj3sX5b5Q86x0ZgYcJxudNiLJK8XrrYqpe9yMoQ4PsN2mL77VtxwiiDrINnW+
eWX5eavIXFd1d6cNbudPy/vS4MpOAMid/g/m53tH8V/ZPUkCQQD7DGcW5ra05dK7
qpcj+TRQACe2VSgo78Li9DoifoU9vdx3pWWNxthdGfUlMXuAyl29sFXsxVE/ve47
k7jf/YSTAkEAzz5j+F28XwRkC+2HEQFTk+CBDsV3iNFNcRFeQiaYXwI6OCmQQXDA
pdmcjFqUzcKh7Wtx3G/Fz8hyifzr4/Xf1QJBAJgSjEP4H8b2zK93h7R32bN4VJYD
gZ9ClYhLLwgEIgwjfXBQlXLLd/b1qWUNU2XRr/Ue4v3ZDP2SvMQEGOI+PNcCQQCF
j3PmEKLhqXbAqSeusegnGTyTRHew2RLLl6Hjh/QS5uCWaVLqmbvOJtxZJ9dWc+Tf
masboX0eV9RZUYLEuySxAkBLfEizykRCZ1CYkIUtKsq6HOtj+ELPBVtVPMCx3O10
LMEOXuCrAMT/nApK629bgSlTU6P9PZd+05yRbHt4Ds1S
-----END RSA PRIVATE KEY-----`)
)

type smtpServer struct {
	//array of commands
	Commands map[string]func(payload []byte) ([]byte, error)
	//function to be called, when no corresponding command is found
	CatchAll func(payload []byte) ([]byte, error)
	//error reporting function
	ErrorReporter func(err error) []byte
	//separator between command and payload
	Separator []byte
}

// Listen creates a server that listens for incoming SMTP connections
func (srv *smtpServer) Listen(network, address string, secure bool) error {
	var l net.Listener
	var err error
	if secure {
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		tlsConfig.Certificates[0], err = tls.X509KeyPair(tlsTestCert, tlsTestKey)
		if err != nil {
			return err
		}
		var tcpL net.Listener
		tcpL, err = net.Listen("tcp", address)
		if err != nil {
			return err
		}
		l = tls.NewListener(tcpL, tlsConfig)
		defer l.Close()
	} else {
		l, err = net.Listen(network, address)
		if err != nil {
			return err
		}
		defer l.Close()
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer func() {
				e := recover()
				if e != nil {
					errorRecovered := e.(string)
					if errorRecovered != "" {
						fmt.Println(errorRecovered)
						c.Write(srv.ErrorReporter(errors.New(errorRecovered)))
						c.Close()
					}
				}
			}()
			c.Write([]byte("Commands available: \n"))
			for command := range srv.Commands {
				c.Write([]byte("# "))
				c.Write([]byte(command))
				c.Write([]byte(" [payload] \n"))
			}
			c.Write([]byte("What to do? ...\n"))

			//reading
			buf := make([]byte, 0, 4096)
			tmp := make([]byte, 256)
			for {
				n, err := conn.Read(tmp)
				if err != nil {
					if err != io.EOF {
						panic(err.Error())
					}
					break
				}
				buf = append(buf, tmp[:n]...)
			}

			parsed := bytes.Split(buf, srv.Separator)
			command := strings.ToLower(string(parsed[0]))
			payload := bytes.Join(parsed[1:], srv.Separator)

			action, ok := srv.Commands[command]
			if !ok {
				action = srv.CatchAll
			}

			answer, err := action(payload)
			if err != nil {
				panic(err.Error())
			} else {
				c.Write(answer)
				c.Close()
			}
		}(conn)
	}
}

func catchAllFunc(payload []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("Catch all command with payload of %v", string(payload))), nil
}

func helloFunc(payload []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("Hello command with payload of %v", string(payload))), nil
}

func badFunc(payload []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("Bad command with payload of %v", string(payload))), errors.New("Ups, sorry!")
}

func errorReporter(err error) []byte {
	return []byte("Error processing the command: " + err.Error())
}

func TestStartFakeSMTPServer(t *testing.T) {
	t.Parallel()
	var commands = make(map[string](func(payload []byte) ([]byte, error)))
	commands["hello"] = helloFunc
	commands["bad"] = badFunc
	separator := []byte(" ")
	go func() {
		serv := smtpServer{commands, catchAllFunc, errorReporter, separator}
		err := serv.Listen("tcp", ":3000", false)
		assert.NoError(t, err)
	}()
}

func TestStartFakeSecureSMTPServer(t *testing.T) {
	t.Parallel()
	var commands = make(map[string](func(payload []byte) ([]byte, error)))
	commands["hello"] = helloFunc
	commands["bad"] = badFunc
	separator := []byte(" ")
	go func() {
		serv := smtpServer{commands, catchAllFunc, errorReporter, separator}
		err := serv.Listen("tcp", ":3030", true)
		assert.NoError(t, err)
	}()
}

func TestFakeSMTPDial(t *testing.T) {
	t.Parallel()
	// give the server some time to start
	time.Sleep(200 * time.Millisecond)
	_, err := net.Dial("tcp", "localhost:3000")
	assert.NoError(t, err)
}

//func TestFakeSMTPSecureDial(t *testing.T) {
//	t.Parallel()
//	// give the server some time to start
//	time.Sleep(200 * time.Millisecond)
//	tlsconfig := &tls.Config{
//		InsecureSkipVerify: true,
//		ServerName:         "localhost",
//	}
//	_, err := tls.Dial("tcp", "localhost:3030", tlsconfig)
//	assert.NoError(t, err)
//}
