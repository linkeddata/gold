package gold

var (
	// Apps contains a list of default apps that get server instead of RDF
	Apps = map[string]string{
		"newCert": `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + SystemPrefix + `/cert">
    <h2>Issue new certificate</h2>
    Name: <input type="text" name="name">
    WebID: <input type="text" name="webid" autocorrect="off">
    <keygen id="spkacWebID" name="spkac" challenge="randomchars" keytype="rsa" hidden></keygen>
    <input type="submit" value="Issue">
    </form>
</body>
</html>`,
		"accountRecovery": `<!DOCTYPE html>
<html id="docHTML">
<body>
    <h2>Recover access to your account</h2>
    <form method="POST">
    What is your WebID?
    <br>
    <input type="url" name="webid" autocorrect="off">
    <input type="submit" value="Recover account">
    </form>
</body>
</html>`,
		"401": `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>401 - Unauthorized! You need to authenticate to access this resource.</h1>
    <form method="POST" action="/` + SystemPrefix + `/login">
    <h2>Login</h2>
    WebID:
    <br>
    <input type="url" name="webid" autocorrect="off">
    <br>
    Password:
    <br>
    <input type="password" name="password">
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + SystemPrefix + `/recovery">Forgot your password?</a></p>
    <br>
    <p>Do you need a WebID? You can sign up for one at <a href="https://databox.me/" target="_blank">databox.me</a>.</p>
</body>
</html>`,
		"403": `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>403 - oh noes, access denied!</h1>
    <h2>Please visit the <a href="/` + SystemPrefix + `/accountRecovery">recovery page</a> in case you have lost access to your credentials.</h2>
</body>
</html>`,
	}
	// SMTPTemplates contains a list of templates for sending emails
	SMTPTemplates = map[string]string{
		"accountRecovery": `<p>Hello,</p>

<p>We have a received a request to recover you account, originating from <strong>{{.IP}}</strong>. Please ignore this email if you did not send this request.</p>

<p>Click the following link to recover your account: <a href="{{.Link}}" target="_blank">{{.Link}}</a></p>

<p>This email was generated automatically. No one will respond if you reply to it.</p>

<p>Sincerely,
<p>{{.Host}} team</p>
`,
		"welcomeMail": `<p>Hi there {{.Name}}!</p>
<br>
<p>It looks like you have successfully created your Solid account on {{.Host}}. Congratulations!</p>

<p>Your WebID (identifier) is: {{.WebID}}.</p>

<p>You can start browsing your files here: {{.Account}}.</p>

<p>We would like to reassure you that we will not use your email address for any other purpose than allowing you to authenticate and/or recover your account credentials.</p>

<p>Best,</p>
<p>{{.Host}} team</p>
`,
	}
)

func NewPassTemplate(token string, err string) string {
	template := `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + SystemPrefix + `/recovery?token=` + token + `">
    <h2>Please provide a new password</h2>
    <p style="color: red;">` + err + `</p>
    Password:
    <br>
    <input type="password" name="password">
    <br>
    Password (type again to verify):
    <br>
    <input type="password" name="verifypass">
    <br>
    <input type="submit" value="Submit">
    </form>
</body>
</html>`
	return template
}

func LoginTemplate(redir, origin, webid string) string {
	template := `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + SystemPrefix + `/login?redirect=` + redir + `&origin=` + origin + `">
    <h2>Login</h2>
    WebID:
    <br>
    <input type="url" name="webid" value="` + webid + `" autocorrect="off">
    <br>
    Password:
    <br>
    <input type="password" name="password" autofocus>
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + SystemPrefix + `/recovery">Forgot your password?</a></p>
    <br>
    <p>Do you need a WebID? You can sign up for one at <a href="https://databox.me/" target="_blank">databox.me</a>.</p>
</body>
</html>`

	return template
}

func UnauthorizedTemplate(redirTo, webid string) string {
	template := `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>401 - Unauthorized! You need to authenticate to access this resource.</h1>
    <form method="POST" action="/` + SystemPrefix + `/login?redirect=` + redirTo + `">
    <h2>Login</h2>
    WebID:
    <br>
    <input type="url" name="webid" value="` + webid + `" autocorrect="off">
    <br>
    Password:
    <br>
    <input type="password" name="password" autofocus>
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + SystemPrefix + `/recovery">Forgot your password?</a></p>
    <br>
    <p>Do you need a WebID? You can sign up for one at <a href="https://databox.me/" target="_blank">databox.me</a>.</p>
</body>
</html>`

	return template
}

func LogoutTemplate(webid string) string {
	template := `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>You are logged in as ` + webid + `.</h1>
    <h2><a href="/` + SystemPrefix + `/logout">Click here to logout</a></h2>
</body>
</html>`
	return template
}

func TokensTemplate(tokens string) string {
	template := `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    ` + tokens + `
</body>
</html>`
	return template
}
