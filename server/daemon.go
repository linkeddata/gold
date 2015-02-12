package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"strings"
	"time"

	"github.com/linkeddata/gold"
)

var (
	bind    = flag.String("bind", "", "bind address (empty: fcgi)")
	cookieT = flag.Duration("cookieAge", 24*time.Hour, "lifetime for cookies")
	debug   = flag.Bool("debug", false, "output extra logging")
	insec   = flag.String("insecure", "", "insecure HTTP listener (for bechmarking, empty: off)")
	root    = flag.String("root", ".", "path to file storage root")
	skin    = flag.String("skin", "tabulator", "default view for HTML clients")
	tlsCert = flag.String("tlsCertFile", "", "TLS certificate eg. cert.pem")
	tlsKey  = flag.String("tlsKeyFile", "", "TLS certificate eg. key.pem")
	vhosts  = flag.Bool("vhosts", false, "append serverName to path on disk")

	tlsConfig = &tls.Config{
		ClientAuth: tls.RequestClientCert,
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

func init() {
	flag.Parse()
	gold.CookieAge = *cookieT
	gold.Debug = *debug
	gold.Skin = *skin
	gold.ServerPort = *bind
}

func main() {
	serverRoot, err := os.Getwd()
	if err != nil {
		println("[Server] Error starting server:", err)
		os.Exit(1)
	}

	if *root != "." {
		if strings.HasPrefix(*root, serverRoot) || strings.HasPrefix(*root, "/") {
			serverRoot = *root
		} else {
			serverRoot = serverRoot + "/" + *root
		}
		if !strings.HasSuffix(*root, "/") {
			serverRoot += "/"
		}
	}

	if *debug {
		println("[Server] ---- Starting server ----")
		println("[Server] Setting root to", serverRoot)
		println("[Server] Listening on port", *bind)
		println("[Server] Using vhosts?", *vhosts)
	}

	handler := gold.NewServer(serverRoot, *vhosts)

	if len(*insec) > 0 {
		err = http.ListenAndServe(*insec, handler)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	var (
		srv  *http.Server
		ltcp net.Listener
		ltls net.Listener
	)

	if bind == nil || len(*bind) == 0 {
		err = fcgi.Serve(nil, handler)
	} else {
		srv = &http.Server{Addr: *bind, Handler: handler}
		tlsConfig.Certificates = make([]tls.Certificate, 1)
		if len(*tlsCert) == 0 && len(*tlsKey) == 0 {
			tlsConfig.Certificates[0], err = tls.X509KeyPair(tlsTestCert, tlsTestKey)
		} else {
			tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		}
		if err == nil {
			ltcp, err = net.Listen("tcp", *bind)
		}
		if err == nil {
			ltls = tls.NewListener(ltcp, tlsConfig)
			err = srv.Serve(ltls)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}
