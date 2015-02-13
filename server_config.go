package gold

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type ServerConfig struct {
	// DataSkin sets the default skin for viewing RDF resources
	DataSkin string

	// Debug (display or hide stdout logging)
	Debug bool

	// DirIndex contains the default index file name
	DirIndex []string

	// DirSkin points to the skin/app for browsing the data space
	DirSkin string

	Root   string
	Vhosts bool
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		DataSkin: "tabulator",
		DirIndex: []string{"index.html", "index.htm"},
		DirSkin:  "http://linkeddata.github.io/warp/#list/",
		Root:     serverDefaultRoot(),
	}
}

func (c *ServerConfig) LoadJSONFile(filename string) error {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &c)
}

func serverDefaultRoot() string {
	serverRoot, err := os.Getwd()
	if err != nil {
		log.Fatalln(err)
	}

	if !strings.HasSuffix(serverRoot, "/") {
		serverRoot += "/"
	}
	return serverRoot
}
