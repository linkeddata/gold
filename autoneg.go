// Package gold implements several LD standards
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// The functions in this package implement the behaviour specified in
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html
//
// This deviates from RFC2616 in one respect. When a client sets their
// Accept header to "*" (which is illegal) it will be interpreted as "*/*".
// This has been observed in the wild, and the choice was made in the
// spirit of being liberal in values that are accepted from the 'net.
package gold

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Accept structure is used to represent a clause in an HTTP Accept Header.
type Accept struct {
	Type, SubType string
	Q             float32
	Params        map[string]string
}

// For internal use, so that we can use the sort interface.
type acceptSorter []Accept

func (accept acceptSorter) Len() int {
	return len(accept)
}

// purposely sorts "backwards" so we have the most appropriate
// (largest q-value) at the beginning of the list.
func (accept acceptSorter) Less(i, j int) bool {
	ai, aj := accept[i], accept[j]
	if ai.Q > aj.Q {
		return true
	}
	if ai.Type != "*" && aj.Type == "*" {
		return true
	}
	if ai.SubType != "*" && aj.SubType == "*" {
		return true
	}
	return false
}

func (accept acceptSorter) Swap(i, j int) {
	accept[i], accept[j] = accept[j], accept[i]
}

// AcceptList is a sorted list of clauses from an Accept header.
type AcceptList []Accept

// Negotiate the most appropriate contentType given the list of alternatives.
// Returns an error if no alternative is acceptable.
func (al AcceptList) Negotiate(alternatives ...string) (contentType string, err error) {
	asp := make([][]string, 0, len(alternatives))
	for _, ctype := range alternatives {
		asp = append(asp, strings.SplitN(ctype, "/", 2))
	}
	for _, clause := range al {
		for i, ctsp := range asp {
			if clause.Type == ctsp[0] && clause.SubType == ctsp[1] {
				contentType = alternatives[i]
				return
			}
			if clause.Type == ctsp[0] && clause.SubType == "*" {
				contentType = alternatives[i]
				return
			}
			if clause.Type == "*" && clause.SubType == "*" {
				contentType = alternatives[i]
				return
			}
		}
	}
	err = errors.New("No acceptable alternatives")
	return
}

// Parse an Accept Header string returning a sorted list of clauses.
func parseAccept(header string) (accept []Accept, err error) {
	header = strings.Trim(header, " ")
	if len(header) == 0 {
		accept = make([]Accept, 0)
		return
	}

	parts := strings.SplitN(header, ",", -1)
	accept = make([]Accept, 0, len(parts))
	for _, part := range parts {
		part := strings.Trim(part, " ")

		a := Accept{}
		a.Params = make(map[string]string)
		a.Q = 1.0

		mrp := strings.SplitN(part, ";", -1)

		mediaRange := mrp[0]
		sp := strings.SplitN(mediaRange, "/", -1)
		a.Type = strings.Trim(sp[0], " ")

		switch {
		case len(sp) == 1 && a.Type == "*":
			// The case where the Accept header is just "*" is strictly speaking
			// invalid but is seen in the wild. We take it to be equivalent to
			// "*/*"
			a.SubType = "*"
		case len(sp) == 2:
			a.SubType = strings.Trim(sp[1], " ")
		default:
			err = errors.New("Invalid media range in " + part)
			return
		}

		if len(mrp) == 1 {
			accept = append(accept, a)
			continue
		}

		for _, param := range mrp[1:] {
			sp := strings.SplitN(param, "=", 2)
			if len(sp) != 2 {
				err = errors.New("Invalid parameter in " + part)
				return
			}
			token := strings.Trim(sp[0], " ")
			if token == "q" {
				q, _ := strconv.ParseFloat(sp[1], 32)
				a.Q = float32(q)
			} else {
				a.Params[token] = strings.Trim(sp[1], " ")
			}
		}

		accept = append(accept, a)
	}

	sorter := acceptSorter(accept)
	sort.Sort(sorter)

	return
}

// Parse the Accept header and return a sorted list of clauses. If the Accept header
// is present but empty this will be an empty list. If the header is not present it will
// default to a wildcard: */*. Returns an error if the Accept header is ill-formed.
func (req *httpRequest) Accept() (al AcceptList, err error) {
	var accept string
	headers, ok := req.Header["Accept"]
	if ok && len(headers) > 0 {
		// if multiple Accept headers are specified just take the first one
		// such a client would be quite broken...
		accept = headers[0]
	} else {
		// default if not present
		accept = "*/*"
	}
	al, err = parseAccept(accept)
	return
}
