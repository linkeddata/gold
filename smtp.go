package gold

import (
	"crypto/tls"
	"fmt"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
)

// EmailConfig holds configuration values for remote SMTP servers
type EmailConfig struct {
	// Name of the remote SMTP server account, i.e. Server admin
	Name string
	// Addr is the remote SMTP server email address, i.e. admin@server.org
	Addr string
	// User is the remote SMTP server username, i.e. admin
	User string
	// Pass is the remote SMTP server password
	Pass string
	// Host is the remote SMTP server IP address or domain
	Host string
	// Port is the remote SMTP server port number
	Port int
	// ForceSSL forces SSL/TLS connection instead of StartTLS
	ForceSSL bool
	// Insecure allows connections to insecure remote SMTP servers (self-signed certs)
	Insecure bool
}

// should be run in a go routine
func (s *Server) sendRecoveryMail(goldHost string, IP string, to []string, link string) {
	if &s.Config.SMTPConfig == nil {
		s.debug.Println("Missing smtp server configuration")
	}
	subject := "Recovery instructions for your account on " + goldHost
	smtpCfg := &s.Config.SMTPConfig

	auth := smtp.PlainAuth("",
		smtpCfg.User,
		smtpCfg.Pass,
		smtpCfg.Host,
	)

	// Setup headers
	src := mail.Address{Name: "", Address: smtpCfg.Addr}
	dst := mail.Address{Name: "", Address: to[0]}
	headers := make(map[string]string)
	headers["From"] = src.String()
	headers["To"] = dst.String()
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"utf-8\""
	// Setup message
	vals := make(map[string]string)
	vals["{{.IP}}"] = IP
	vals["{{.From}}"] = smtpCfg.Name
	vals["{{.Link}}"] = link
	body := parseMailTemplate("accountRecovery", vals)

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	if len(smtpCfg.Host) > 0 && smtpCfg.Port > 0 && auth != nil {
		smtpServer := smtpCfg.Host + ":" + strconv.Itoa(smtpCfg.Port)
		var err error
		// force upgrade to full SSL/TLS connection
		if smtpCfg.ForceSSL {
			err = s.sendSecureRecoveryMail(src, dst, []byte(message), smtpCfg)
		} else {
			err = smtp.SendMail(smtpServer, auth, smtpCfg.Addr, to, []byte(message))
		}
		if err != nil {
			s.debug.Println("Error sending recovery email to " + to[0] + ": " + err.Error())
		} else {
			s.debug.Println("Successfully sent recovery email to " + to[0])
		}
	} else {
		s.debug.Println("Missing smtp server and/or port")
	}
}

func (s *Server) sendSecureRecoveryMail(from mail.Address, to mail.Address, msg []byte, cfg *EmailConfig) (err error) {
	// Connect to the SMTP Server
	serverName := cfg.Host + ":" + strconv.Itoa(cfg.Port)
	auth := smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)

	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: s.Config.SMTPConfig.Insecure,
		ServerName:         cfg.Host,
	}

	// Here is the key, you need to call tls.Dial instead of smtp.Dial
	// for smtp servers running on 465 that require an ssl connection
	// from the very beginning (no starttls)
	conn, err := tls.Dial("tcp", serverName, tlsconfig)
	if err != nil {
		s.debug.Println(err.Error())
		return
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		s.debug.Println(err.Error())
		return
	}

	// Auth
	if err = c.Auth(auth); err != nil {
		s.debug.Println(err.Error())
		return
	}

	// To && From
	if err = c.Mail(from.Address); err != nil {
		s.debug.Println(err.Error())
		return
	}

	if err = c.Rcpt(to.Address); err != nil {
		s.debug.Println(err.Error())
		return
	}

	// Data
	w, err := c.Data()
	if err != nil {
		s.debug.Println(err.Error())
		return
	}

	_, err = w.Write(msg)
	if err != nil {
		s.debug.Println(err.Error())
		return
	}

	err = w.Close()
	if err != nil {
		s.debug.Println(err.Error())
		return
	}

	c.Quit()
	return nil
}

func parseMailTemplate(tpl string, vals map[string]string) string {
	body := SMTPTemplates[tpl]

	for oVal, nVal := range vals {
		body = strings.Replace(body, oVal, nVal, -1)
	}
	return body
}
