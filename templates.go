package gold

var (
	// Apps contains a list of default apps that get server instead of RDF
	Apps = map[string]string{
		"tabulator": `<!DOCTYPE html>
<html id="docHTML">
<head>
    <link type="text/css" rel="stylesheet" href="https://w3.scripts.mit.edu/tabulator/tabbedtab.css" />
    <script type="text/javascript" src="https://w3.scripts.mit.edu/tabulator/js/mashup/mashlib.js"></script>
<script>

document.addEventListener('DOMContentLoaded', function() {
    $rdf.Fetcher.crossSiteProxyTemplate = document.origin + '/` + ProxyPath + `?uri={uri}';
    var uri = window.location.href;
    window.document.title = uri;
    var kb = tabulator.kb;
    var subject = kb.sym(uri);
    tabulator.outline.GotoSubject(subject, true, undefined, true, undefined);
});
</script>
</head>
<body>
<div class="TabulatorOutline" id="DummyUUID">
    <table id="outline"></table>
</div>
</body>
</html>`,
		"newCert": `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + SystemPrefix + `/newCert">
    <h2>Issue new certificate</h2>
    Name: <input type="text" name="name">
    WebID: <input type="text" name="webid">
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
    <input type="text" name="webid">
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
    <input type="text" name="webid">
    <br>
    Password:
    <br>
    <input type="password" name="password">
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + SystemPrefix + `/accountRecovery">Forgot your password?</a></p>
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
		"404": `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>404 - oh noes, there's nothing here</h1>
</body>
</html>`,
	}
	// SMTPTemplates contains a list of templates for sending emails
	SMTPTemplates = map[string]string{
		"accountRecovery": `<p>Hello,</p>

<p>We have a received a request to recover you account, originating from <strong>{{.IP}}</strong>. Please ignore this email if you did not send this request.</p>

<p>Click the following link to recover your account: <a href="{{.Link}}" target="_blank">{{.Link}}</a></p>

<p>This email was generated automatically. No one will respond if you reply to it.</p>

<p>Sincerely,<br>
{{.From}}</p>
`,
		"welcomeMail": `<p>Hello {{.Name}},</p>
<p>It looks like you have successfully created your WebID and Solid account on {{.Host}}. Congratulations!</p>

<p>Here are some useful things you can do right away:</p>
<p>* you can start browsing your files here: {{.AccountURI}}.</p>
<p>* you can manage your personal profile information here: {{.ProfileEditor}}</p>

<p>We would like to kindly remind you that we will not use your email address for any other purpose than allowing you to authenticate and/or recover your account credentials.</p>

<p>Best,</p>
<p>{{.Host}} team</p>
`,
	}
)

func NewPassTemplate(token string, err string) string {
	template := `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + SystemPrefix + `/accountRecovery?token=` + token + `">
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

func LoginTemplate(redir string) string {
	template := `<!DOCTYPE html>
<html id="docHTML">
<body>
    <form method="POST" action="/` + SystemPrefix + `/login?redirect=` + redir + `">
    <h2>Login</h2>
    WebID:
    <br>
    <input type="text" name="webid">
    <br>
    Password:
    <br>
    <input type="password" name="password">
    <br>
    <input type="submit" value="Login">
    </form>
    <p><a href="/` + SystemPrefix + `/accountRecovery">Forgot your password?</a></p>
    <br>
    <p>Do you need a WebID? You can sign up for one at <a href="https://databox.me/" target="_blank">databox.me</a>.</p>
</body>
</html>`

	return template
}
