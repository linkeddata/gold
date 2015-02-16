package gold

type SPARQLResults struct {
	Head struct {
		Vars []string
	}
	Results struct {
		Ordered  bool
		Distinct bool
		Bindings []map[string]struct {
			Type  string
			Value string
		}
	}
}
