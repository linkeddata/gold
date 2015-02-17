package gold

import (
	"bytes"
	"net/smtp"
	"strconv"
	"text/template"
)

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
}

type SMTPTemplateData struct {
	// From is the name of the email account holder
	From string
	// To is the recipient's email address
	To string
	// Subject for email
	Subject string
	// Body for email
	Body string
}

// should be run in a go routine
func (s *Server) sendMail(goldHost string, to []string, msg string, tpl string) {
	if &s.Config.SMTPConfig == nil {
		s.debug.Println("Missing smtp server configuration")
	}
	smtpCfg := &s.Config.SMTPConfig
	context := &SMTPTemplateData{
		smtpCfg.Name,
		to[0],
		"Recovery instructions for your account on " + goldHost,
		msg,
	}
	t := template.New(tpl)
	t, err := t.Parse(SMTPTemplates[tpl])
	if err != nil {
		s.debug.Println("Error trying to parse mail template")
	}
	var body bytes.Buffer
	err = t.Execute(&body, context)
	if err != nil {
		s.debug.Println("Error trying to execute mail template")
	}

	auth := smtp.PlainAuth("",
		smtpCfg.User,
		smtpCfg.Pass,
		smtpCfg.Host,
	)

	if len(smtpCfg.Host) > 0 && smtpCfg.Port > 0 {
		smtpServer := smtpCfg.Host + ":" + strconv.Itoa(smtpCfg.Port)
		err = smtp.SendMail(smtpServer, auth, smtpCfg.Addr, to, body.Bytes())
		if err != nil {
			println(err.Error())
			s.debug.Println("Error sending email to " + to[0] + ": " + err.Error())
		}
	} else {
		s.debug.Println("Missing smtp server and/or port")
	}
}
