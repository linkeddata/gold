// Package apps provides functions for rendering application templates
// TODO: implement strategy pattern
package apps

import(
	"strings"
	"html/template"
	"log"
	"fmt"
	"io/ioutil"

	"github.com/linkeddata/gold/pkg/routes"
)

var(
	apps = map[string]string {
		"DataApp": "templates/tabulator.html",
		"404": routes.NotFound(),
	}
	templates = template.New("")
)

// DataApp renders Data application template
func DataApp()(string, error) {
	app, err := render("DataApp", template.URL(routes.Popup()))
	if err != nil {
		return "", fmt.Errorf("Failed to render DataApp: %v", err)
	}
	return app, nil
}

// NotFound returns 404 page
func NotFound()(string, error) {
	app, err := render("404", nil)
	if err != nil {
		return "", fmt.Errorf("Failed to render NotFound: %v", err)
	}
	return app, nil
}

func render(name string, data interface{})(string, error) {
	var writer strings.Builder
	err := templates.ExecuteTemplate(&writer, name, data)
	if err != nil {
		return "", err
	}
	return writer.String(), nil
}
	
func init() {
	for app, path := range(apps) {
		tmpFile, err := ioutil.ReadFile(path)
		if err != nil {
			log.Panicf("Failed to read template file %s: %v", path, err)
		}

		_, err = templates.New(app).Parse(string(tmpFile))
		if err != nil {
			log.Panicf("Failed to parse template for %s: %v", app, err)
		}
	}
}
