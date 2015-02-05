package gold

var (
	// Skins contains a list of skins that get server instead of RDF
	Skins = map[string]string{
		"tabulator": `<!DOCTYPE html>
<html id="docHTML">
<head>
    <link type="text/css" rel="stylesheet" href="https://w3.scripts.mit.edu/tabulator/tabbedtab.css" />
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
    <script type="text/javascript" src="https://w3.scripts.mit.edu/tabulator/js/mashup/mashlib.js"></script>
<script>
jQuery.ajaxPrefilter(function(options) {
    if (options.crossDomain) {
        options.url = "https://data.fm/proxy?uri=" + encodeURIComponent(options.url);
    }
});
jQuery(document).ready(function() {
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
		"404": `<!DOCTYPE html>
<html id="docHTML">
<head>
</head>
<body>
    <h1>404 - oh noes, there's nothing here</h1>
</body>
</html>`,
	}
)
