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

	httpA          = flag.String("http", ":80", "HTTP listener address (redirects to HTTPS)")
	httpsA         = flag.String("https", ":443", "HTTPS listener address")
	insecure       = flag.Bool("insecure", false, "provide insecure/plain HTTP access (only)")
	nohttp         = flag.Bool("nohttp", false, "disable HTTP redirects to HTTPS?")
	hsts           = flag.Bool("enabbleHSTS", true, "enable strict transport security (HSTS)?")
	enableWebIDTLS = flag.Bool("enabbleWebIDTLS", true, "enable WebID-TLS authentication?")

	cookieT = flag.Int64("cookieAge", 24, "lifetime for cookies (in hours)")
	debug   = flag.Bool("debug", false, "output extra logging?")
	root    = flag.String("root", ".", "path to file storage root")
	app     = flag.String("app", "tabulator", "default viewer app for HTML clients")
	tlsCert = flag.String("tlsCertFile", "", "TLS certificate eg. cert.pem")
	tlsKey  = flag.String("tlsKeyFile", "", "TLS certificate eg. key.pem")
	vhosts  = flag.Bool("vhosts", false, "run in virtual hosts mode?")
	bolt    = flag.String("boltPath", "", "path to the location of the Bolt db file (uses /tmp/bolt.db by default)")

	metaSuffix = flag.String("metaSuffix", ",meta", "default suffix for meta files")
	aclSuffix  = flag.String("aclSuffix", ",acl", "default suffix for ACL files")

	proxy = flag.String("proxy", "", "URL of the proxy service used for WebID-TLS delegation")
	local = flag.Bool("proxyLocal", true, "set to false to disable proxying of resource from local network")

	tokenT = flag.Int64("tokenAge", 5, "recovery token lifetime (in minutes)")

	salt = flag.String("salt", "", "used for storing hashed user passwords")

	agent = flag.String("agent", "", "WebID of the agent used for delegated authentication")

	emailName     = flag.String("emailName", "", "remote SMTP server account name")
	emailAddr     = flag.String("emailAddr", "", "remote SMTP server email address")
	emailUser     = flag.String("emailUser", "", "remote SMTP server username")
	emailPass     = flag.String("emailPass", "", "remote SMTP server password")
	emailServ     = flag.String("emailServ", "", "remote SMTP server address / domain")
	emailPort     = flag.String("emailPort", "", "remote SMTP port number")
	emailForceSSL = flag.Bool("emailForceSSL", false, "force SSL/TLS connection for remote SMTP server?")
	emailInsecure = flag.Bool("emailInsecure", false, "allow connections to insecure remote SMTP servers (self-signed certs)?")

	httpsPort string
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
	// Try to recover in case of panics
	defer func() {
		if rec := recover(); rec != nil {
			log.Println("\nRecovered from panic: ", rec)
		}
	}()

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
		config.WebIDTLS = *enableWebIDTLS
		config.Salt = *salt
		config.CookieAge = *cookieT
		config.TokenAge = *tokenT
		config.Debug = *debug
		config.DataRoot = serverRoot
		config.BoltPath = *bolt
		config.Vhosts = *vhosts
		config.Insecure = *insecure
		config.NoHTTP = *nohttp
		config.HSTS = *hsts
		config.MetaSuffix = *metaSuffix
		config.ACLSuffix = *aclSuffix
		config.Agent = *agent
		config.ProxyTemplate = *proxy
		config.ProxyLocal = *local
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

	// Start Bolt
	err = handler.StartBolt()
	if err != nil {
		log.Fatalln(err)
	}
	defer handler.BoltDB.Close()

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

	tlsConfig := NewTLSConfig(config.WebIDTLS)

	tlsConfig.Certificates = make([]tls.Certificate, 1)
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
