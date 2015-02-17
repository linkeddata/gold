package gold

// #cgo CFLAGS: -I/usr/local/include/rasqal -I/usr/local/include/raptor2 -I/usr/include/rasqal -I/usr/include/raptor2 -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -L/usr/local/lib/redland -lrdf
// #include <stdlib.h>
// #include <librdf.h>
import "C"

import (
	"unsafe"
)

var (
	cGuess      = C.CString("guess")
	cMemory     = C.CString("memory")
	cJson       = C.CString("json")
	cSparql     = C.CString("sparql")
	cTextTurtle = C.CString("text/turtle")
	cJsonSparql = C.CString("http://www.w3.org/2001/sw/DataAccess/json-sparql/")
)

// SPARQL provides standard querying of Graphs
type SPARQL struct {
	baseURI string
	graph   AnyGraph

	cbase *C.char
	rbase *C.struct_raptor_uri_s

	world   *C.struct_librdf_world_s
	storage *C.struct_librdf_storage_s
	model   *C.struct_librdf_model_s
	query   *C.struct_librdf_query_s
	results *C.struct_librdf_query_results_s
}

// NewSPARQL creates a new SPARQL object
func NewSPARQL(baseURI string) *SPARQL {
	r := &SPARQL{
		baseURI: baseURI,
		world:   C.librdf_new_world(),
	}
	r.cbase = C.CString(r.baseURI)
	r.rbase = C.librdf_new_uri(r.world, (*C.uchar)(unsafe.Pointer(r.cbase)))
	r.storage = C.librdf_new_storage(r.world, cMemory, nil, nil)
	r.model = C.librdf_new_model(r.world, r.storage, nil)
	return r
}

func (sparql *SPARQL) Free() {
	// TODO:travis missing this symbol
	// C.librdf_free_memory(unsafe.Pointer(sparql.rbase))
	C.free(unsafe.Pointer(sparql.cbase))
}

// Parse parses a SPARQL query from the reader
func (sparql *SPARQL) Parse(query string) error {
	cquery := C.CString(query)
	sparql.query = C.librdf_new_query(sparql.world, cSparql, nil, (*C.uchar)(unsafe.Pointer(cquery)), sparql.rbase)
	C.free(unsafe.Pointer(cquery))
	return nil
}

func (sparql *SPARQL) Load(uri string) error {
	p := C.librdf_new_parser(sparql.world, cGuess, nil, nil)
	curi := C.CString(uri)
	ruri := C.librdf_new_uri(sparql.world, (*C.uchar)(unsafe.Pointer(curi)))
	C.librdf_parser_parse_into_model(p, ruri, sparql.rbase, sparql.model)
	C.librdf_free_parser(p)
	C.librdf_free_uri(ruri)
	C.free(unsafe.Pointer(curi))
	return nil
}

func (sparql *SPARQL) Execute() {
	sparql.results = C.librdf_model_query_execute(sparql.model, sparql.query)
}

func (sparql *SPARQL) Results() []byte {
	uc := C.librdf_query_results_to_string2(sparql.results, cJson, nil, nil, sparql.rbase)
	return []byte(C.GoString((*C.char)(unsafe.Pointer(uc))))
}
