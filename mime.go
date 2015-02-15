package gold

import (
	crdf "github.com/presbrey/goraptor"
)

var mimeParser = map[string]string{
	"application/ld+json":       "jsonld",
	"application/json":          "internal",
	"application/sparql-update": "internal",
}

var mimeSerializer = map[string]string{
	"application/ld+json": "internal",
	"text/html":           "internal",
}

var mimeTypes = map[string]string{
	".js":   "application/javascript",
	".css":  "text/css; charset=utf-8",
	".htm":  "text/html; charset=utf-8",
	".html": "text/html; charset=utf-8",
	".txt":  "text/plain; charset=utf-8",
	".xml":  "text/xml; charset=utf-8",

	".gif":  "image/gif",
	".jpg":  "image/jpeg",
	".png":  "image/png",
	".svg":  "image/svg+xml",
	".svgz": "image/svg+xml",
	".tif":  "image/tiff",
	".tiff": "image/tiff",
	".wbmp": "image/vnd.wap.wbmp",
	".webp": "image/webp",
	".ico":  "image/x-icon",
	".jng":  "image/x-jng",
	".bmp":  "image/x-ms-bmp",

	".mid":  "audio/midi",
	".midi": "audio/midi",
	".kar":  "audio/midi",
	".mp3":  "audio/mpeg",
	".ogg":  "audio/ogg",
	".m4a":  "audio/x-m4a",
	".ra":   "audio/x-realaudio",

	".3gpp": "video/3gpp",
	".3gp":  "video/3gpp",
	".ts":   "video/mp2t",
	".mp4":  "video/mp4",
	".mpeg": "video/mpeg",
	".mpg":  "video/mpeg",
	".mov":  "video/quicktime",
	".webm": "video/webm",
	".flv":  "video/x-flv",
	".m4v":  "video/x-m4v",
	".mng":  "video/x-mng",
	".asx":  "video/x-ms-asf",
	".asf":  "video/x-ms-asf",
	".wmv":  "video/x-ms-wmv",
	".avi":  "video/x-msvideo",

	".htc": "text/x-component",
	".jad": "text/vnd.sun.j2me.app-descriptor",
	".mml": "text/mathml",
	".wml": "text/vnd.wap.wml",

	".atom":    "application/atom+xml",
	".rss":     "application/rss+xml",
	".woff":    "application/font-woff",
	".jar":     "application/java-archive",
	".war":     "application/java-archive",
	".ear":     "application/java-archive",
	".json":    "application/json",
	".hqx":     "application/mac-binhex40",
	".doc":     "application/msword",
	".pdf":     "application/pdf",
	".ps":      "application/postscript",
	".eps":     "application/postscript",
	".ai":      "application/postscript",
	".rtf":     "application/rtf",
	".m3u8":    "application/vnd.apple.mpegurl",
	".xls":     "application/vnd.ms-excel",
	".eot":     "application/vnd.ms-fontobject",
	".ppt":     "application/vnd.ms-powerpoint",
	".wmlc":    "application/vnd.wap.wmlc",
	".kml":     "application/vnd.google-earth.kml+xml",
	".kmz":     "application/vnd.google-earth.kmz",
	".7z":      "application/x-7z-compressed",
	".cco":     "application/x-cocoa",
	".jardiff": "application/x-java-archive-diff",
	".jnlp":    "application/x-java-jnlp-file",
	".run":     "application/x-makeself",
	".pl":      "application/x-perl",
	".pm":      "application/x-perl",
	".prc":     "application/x-pilot",
	".pdb":     "application/x-pilot",
	".rar":     "application/x-rar-compressed",
	".rpm":     "application/x-redhat-package-manager",
	".sea":     "application/x-sea",
	".swf":     "application/x-shockwave-flash",
	".sit":     "application/x-stuffit",
	".tcl":     "application/x-tcl",
	".tk":      "application/x-tcl",
	".der":     "application/x-x509-ca-cert",
	".pem":     "application/x-x509-ca-cert",
	".crt":     "application/x-x509-ca-cert",
	".xpi":     "application/x-xpinstall",
	".xhtml":   "application/xhtml+xml",
	".xspf":    "application/xspf+xml",
	".zip":     "application/zip",
	".bin":     "application/octet-stream",
	".exe":     "application/octet-stream",
	".dll":     "application/octet-stream",
	".deb":     "application/octet-stream",
	".dmg":     "application/octet-stream",
	".iso":     "application/octet-stream",
	".img":     "application/octet-stream",
	".msi":     "application/octet-stream",
	".msp":     "application/octet-stream",
	".msm":     "application/octet-stream",
	".docx":    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xlsx":    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".pptx":    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

var (
	serializerMimes = []string{}
)

func init() {
	for _, syntax := range crdf.ParserSyntax {
		switch syntax.MimeType {
		case "", "text/html":
			continue
		}
		mimeParser[syntax.MimeType] = syntax.Name
	}
	mimeParser["text/n3"] = mimeParser["text/turtle"]

	for name, syntax := range crdf.SerializerSyntax {
		switch name {
		case "json-triples":
			// only activate: json
			continue
		case "rdfxml-xmp", "rdfxml":
			// only activate: rdfxml-abbrev
			continue
		}
		mimeSerializer[syntax.MimeType] = syntax.Name
	}
	for mime := range mimeSerializer {
		switch mime {
		case "application/xhtml+xml":
			continue
		}
		serializerMimes = append(serializerMimes, mime)
	}
}
