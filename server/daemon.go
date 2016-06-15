package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"strconv"
	"strings"

	"github.com/linkeddata/gold"
)

var (
	conf = flag.String("conf", "", "use this configuration file")

	httpA    = flag.String("http", ":80", "HTTP listener address (redirects to HTTPS)")
	httpsA   = flag.String("https", ":443", "HTTPS listener address")
	insecure = flag.Bool("insecure", false, "provide insecure/plain HTTP access (only)")
	nohttp   = flag.Bool("nohttp", false, "disable HTTP redirects to HTTPS?")

	cookieT = flag.Int64("cookieAge", 24, "lifetime for cookies (in hours)")
	debug   = flag.Bool("debug", false, "output extra logging?")
	root    = flag.String("root", ".", "path to file storage root")
	app     = flag.String("app", "tabulator", "default viewer app for HTML clients")
	tlsCert = flag.String("tlsCertFile", "", "TLS certificate eg. cert.pem")
	tlsKey  = flag.String("tlsKeyFile", "", "TLS certificate eg. key.pem")
	vhosts  = flag.Bool("vhosts", false, "run in virtual hosts mode?")

	metaSuffix = flag.String("metaSuffix", ",meta", "default suffix for meta files")
	aclSuffix  = flag.String("aclSuffix", ",acl", "default suffix for ACL files")

	tokenT = flag.Int64("tokenAge", 5, "recovery token lifetime (in minutes)")

	authProtocol = flag.String("authProtocol", "webid", "authentication protocol (webid-tls / webid-rsa)")

	emailName     = flag.String("emailName", "", "remote SMTP server account name")
	emailAddr     = flag.String("emailAddr", "", "remote SMTP server email address")
	emailUser     = flag.String("emailUser", "", "remote SMTP server username")
	emailPass     = flag.String("emailPass", "", "remote SMTP server password")
	emailServ     = flag.String("emailServ", "", "remote SMTP server address / domain")
	emailPort     = flag.String("emailPort", "", "remote SMTP port number")
	emailForceSSL = flag.Bool("emailForceSSL", false, "force SSL/TLS connection for remote SMTP server?")
	emailInsecure = flag.Bool("emailInsecure", false, "allow connections to insecure remote SMTP servers (self-signed certs)?")

	httpsPort string

	tlsConfig = &tls.Config{
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
		ClientAuth:   tls.RequestClientCert,
		NextProtos:   []string{"http/1.1"},
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
}

func redir(w http.ResponseWriter, req *http.Request) {
	host, _, _ := net.SplitHostPort(req.Host)
	if host == "" {
		host = req.Host
	}
	next := "https://" + host
	if httpsPort != "443" {
		next += ":" + httpsPort
	}
	http.Redirect(w, req, next+req.RequestURI, http.StatusMovedPermanently)
}

func main() {
	serverRoot, err := os.Getwd()
	if err != nil {
		println("[Server] Error starting server:", err)
		os.Exit(1)
	}

	if *root == "." {
		*root = ""
	}

	if strings.HasPrefix(*root, serverRoot) || strings.HasPrefix(*root, "/") {
		serverRoot = *root
	} else {
		serverRoot = serverRoot + "/" + *root
	}
	if !strings.HasSuffix(serverRoot, "/") {
		serverRoot += "/"
	}

	config := gold.NewServerConfig()
	confLoaded := false
	if len(*conf) > 0 {
		err = config.LoadJSONFile(*conf)
		if err == nil {
			confLoaded = true
		} else {
			log.Println(err)
		}
	}
	if !confLoaded {
		config.ListenHTTP = *httpA
		config.ListenHTTPS = *httpsA
		config.TLSCert = *tlsCert
		config.TLSKey = *tlsKey
		config.CookieAge = *cookieT
		config.TokenAge = *tokenT
		config.AuthProtocol = *authProtocol
		config.Debug = *debug
		config.DataRoot = serverRoot
		config.Vhosts = *vhosts
		config.Insecure = *insecure
		config.NoHTTP = *nohttp
		config.MetaSuffix = *metaSuffix
		config.ACLSuffix = *aclSuffix
		if len(*emailName) > 0 && len(*emailAddr) > 0 && len(*emailUser) > 0 &&
			len(*emailPass) > 0 && len(*emailServ) > 0 && len(*emailPort) > 0 {
			ep, _ := strconv.Atoi(*emailPort)
			config.SMTPConfig = gold.EmailConfig{
				Name:     *emailName,
				Addr:     *emailAddr,
				User:     *emailUser,
				Pass:     *emailPass,
				Host:     *emailServ,
				Port:     ep,
				ForceSSL: *emailForceSSL,
				Insecure: *emailInsecure,
			}
		}
	}
	_, httpsPort, _ = net.SplitHostPort(config.ListenHTTPS)

	handler := gold.NewServer(config)

	if os.Getenv("FCGI_ROLE") != "" {
		err = fcgi.Serve(nil, handler)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	if config.Insecure {
		err = http.ListenAndServe(config.ListenHTTP, handler)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	if !config.NoHTTP {
		go func() {
			err = http.ListenAndServe(config.ListenHTTP, http.HandlerFunc(redir))
			if err != nil {
				log.Fatalln(err)
			}
		}()
	}

	var (
		srv  = &http.Server{Addr: config.ListenHTTPS, Handler: handler}
		tcpL net.Listener
		tlsL net.Listener
	)

	tlsConfig.Certificates = make([]tls.Certificate, 1)
	tlsConfig.MinVersion = tls.VersionTLS10
	if config.AuthProtocol != "webid" {
		tlsConfig.ClientAuth = tls.NoClientCert
	}
	if len(config.TLSCert) == 0 && len(config.TLSKey) == 0 {
		tlsConfig.Certificates[0], err = tls.X509KeyPair(tlsTestCert, tlsTestKey)
	} else {
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	}
	if err == nil {
		tcpL, err = net.Listen("tcp", config.ListenHTTPS)
	}
	if err == nil {
		tlsL = tls.NewListener(tcpL, tlsConfig)
		err = srv.Serve(tlsL)
	}
	if err != nil {
		log.Fatal(err)
	}
}
