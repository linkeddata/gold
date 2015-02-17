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
	"time"

	"github.com/linkeddata/gold"
)

var (
	conf = flag.String("conf", "", "use this configuration file")

	httpA    = flag.String("http", ":80", "HTTP listener address (redirects to HTTPS)")
	httpsA   = flag.String("https", ":443", "HTTPS listener address")
	insecure = flag.Bool("insecure", false, "provide insecure/plain HTTP access (only)")
	nohttp   = flag.Bool("nohttp", false, "disable HTTP redirects to HTTPS")

	cookieT = flag.Duration("cookieAge", 24*time.Hour, "lifetime for cookies (in hours)")
	debug   = flag.Bool("debug", false, "output extra logging")
	root    = flag.String("root", ".", "path to file storage root")
	skin    = flag.String("skin", "tabulator", "default view for HTML clients")
	tlsCert = flag.String("tlsCertFile", "", "TLS certificate eg. cert.pem")
	tlsKey  = flag.String("tlsKeyFile", "", "TLS certificate eg. key.pem")
	vhosts  = flag.Bool("vhosts", false, "append serverName to path on disk")

	tokenT = flag.Duration("tokenAge", 5*time.Minute, "recovery token lifetime (in minutes)")

	emailName = flag.String("emailName", "", "remote SMTP server account name")
	emailAddr = flag.String("emailAddr", "", "remote SMTP server email address")
	emailUser = flag.String("emailUser", "", "remote SMTP server username")
	emailPass = flag.String("emailPass", "", "remote SMTP server password")
	emailServ = flag.String("emailServ", "", "remote SMTP server address / domain")
	emailPort = flag.String("emailPort", "", "remote SMTP port number")

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
	if len(*conf) > 0 {
		err = config.LoadJSONFile(*conf)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		config.CookieAge = *cookieT
		config.TokenAge = *tokenT
		config.Debug = *debug
		config.Root = serverRoot
		config.Vhosts = *vhosts
		if len(*emailName) > 0 && len(*emailAddr) > 0 && len(*emailUser) > 0 &&
			len(*emailPass) > 0 && len(*emailServ) > 0 && len(*emailPort) > 0 {
			ep, _ := strconv.Atoi(*emailPort)
			config.SMTPConfig = gold.EmailConfig{
				Name: *emailName,
				Addr: *emailAddr,
				User: *emailUser,
				Pass: *emailPass,
				Host: *emailServ,
				Port: ep,
			}
		}
	}

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
