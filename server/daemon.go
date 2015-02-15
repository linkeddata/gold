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
	httpA    = flag.String("http", ":8080", "HTTP listener address (redirects to HTTPS)")
	httpsA   = flag.String("https", ":8443", "HTTPS listener address")
	insecure = flag.Bool("insecure", false, "provide insecure/plain HTTP access (only)")
	nohttp   = flag.Bool("nohttp", false, "disable HTTP redirects to HTTPS")

	cookieT = flag.Duration("cookieAge", 24*time.Hour, "lifetime for cookies")
	debug   = flag.Bool("debug", false, "output extra logging")
	root    = flag.String("root", ".", "path to file storage root")
	skin    = flag.String("skin", "tabulator", "default view for HTML clients")
	tlsCert = flag.String("tlsCertFile", "", "TLS certificate eg. cert.pem")
	tlsKey  = flag.String("tlsKeyFile", "", "TLS certificate eg. key.pem")
	vhosts  = flag.Bool("vhosts", false, "append serverName to path on disk")

	httpsPort string
)

func init() {
	flag.Parse()
	_, httpsPort, _ = net.SplitHostPort(*httpsA)
}

func redir(w http.ResponseWriter, req *http.Request) {
	host, _, _ := net.SplitHostPort(req.Host)
	if host == "" {
		host = req.Host
	}
	http.Redirect(w, req, "https://"+host+":"+httpsPort+req.RequestURI, http.StatusMovedPermanently)
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

	gold.CookieAge = *cookieT
	config := gold.NewServerConfig()
	config.Debug = *debug
	config.Root = serverRoot
	config.Vhosts = *vhosts
	handler := gold.NewServer(config)

	if os.Getenv("FCGI_ROLE") != "" {
		err = fcgi.Serve(nil, handler)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	if *insecure {
		err = http.ListenAndServe(*httpA, handler)
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	if !*nohttp {
		go func() {
			err = http.ListenAndServe(*httpA, http.HandlerFunc(redir))
			if err != nil {
				log.Fatalln(err)
			}
		}()
	}

	var (
		srv  *http.Server = &http.Server{Addr: *httpsA, Handler: handler}
		tcpL net.Listener
		tlsL net.Listener
	)

	tlsConfig.Certificates = make([]tls.Certificate, 1)
	if len(*tlsCert) == 0 && len(*tlsKey) == 0 {
		tlsConfig.Certificates[0], err = tls.X509KeyPair(tlsTestCert, tlsTestKey)
	} else {
		tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	}
	if err == nil {
		tcpL, err = net.Listen("tcp", *httpsA)
	}
	if err == nil {
		tlsL = tls.NewListener(tcpL, tlsConfig)
		err = srv.Serve(tlsL)
	}
	if err != nil {
		log.Fatal(err)
	}
}
