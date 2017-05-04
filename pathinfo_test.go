package gold

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathInfoWithoutTrailingSlash(t *testing.T) {
	sroot := serverDefaultRoot()
	req := &httpRequest{nil, handler, "", "", "", false}
	p, err := req.pathInfo(testServer.URL)
	assert.Nil(t, err)
	assert.Equal(t, testServer.URL+"/", p.URI)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "", p.Path)
	assert.Equal(t, sroot, p.File)
	assert.Equal(t, testServer.URL+"/"+config.ACLSuffix, p.AclURI)
	assert.Equal(t, sroot+config.ACLSuffix, p.AclFile)
	assert.Equal(t, testServer.URL+"/"+config.MetaSuffix, p.MetaURI)
	assert.Equal(t, sroot+config.MetaSuffix, p.MetaFile)
	assert.Empty(t, p.Extension)
	assert.True(t, p.Exists)
}

func TestPathInfoWithTrailingSlash(t *testing.T) {
	sroot := serverDefaultRoot()
	req := &httpRequest{nil, handler, "", "", "", false}

	p, err := req.pathInfo(testServer.URL + "/")
	assert.Nil(t, err)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, testServer.URL+"/", p.URI)
	assert.Equal(t, "", p.Path)
	assert.Equal(t, sroot, p.File)
	assert.Equal(t, testServer.URL+"/"+config.ACLSuffix, p.AclURI)
	assert.Equal(t, sroot+config.ACLSuffix, p.AclFile)
	assert.Equal(t, testServer.URL+"/"+config.MetaSuffix, p.MetaURI)
	assert.Equal(t, sroot+config.MetaSuffix, p.MetaFile)
	assert.Empty(t, p.Extension)
	assert.True(t, p.Exists)
}

func TestPathInfoWithPath(t *testing.T) {
	path := testServer.URL + "/_test/"
	sroot := serverDefaultRoot()
	req := &httpRequest{nil, handler, "", "", "", false}

	p, err := req.pathInfo(path)
	assert.Nil(t, err)
	assert.Equal(t, path, p.URI)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/", p.Path)
	assert.Equal(t, sroot+"_test/", p.File)
	assert.Equal(t, path+config.ACLSuffix, p.AclURI)
	assert.Equal(t, sroot+"_test/"+config.ACLSuffix, p.AclFile)
	assert.Equal(t, path+config.MetaSuffix, p.MetaURI)
	assert.Equal(t, sroot+"_test/"+config.MetaSuffix, p.MetaFile)
	assert.Empty(t, p.Extension)
	assert.True(t, p.Exists)
}

func TestPathInfoWithPathAndChildDir(t *testing.T) {
	path := testServer.URL + "/_test/"
	sroot := serverDefaultRoot()
	req := &httpRequest{nil, handler, "", "", "", false}

	p, err := req.pathInfo(path + "dir/")
	assert.Nil(t, err)
	assert.Equal(t, path+"dir/", p.URI)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/dir/", p.Path)
	assert.Equal(t, path, p.ParentURI)
	assert.Equal(t, sroot+"_test/dir/", p.File)
	assert.Equal(t, path+"dir/"+config.ACLSuffix, p.AclURI)
	assert.Equal(t, sroot+"_test/dir/"+config.ACLSuffix, p.AclFile)
	assert.Equal(t, path+"dir/"+config.MetaSuffix, p.MetaURI)
	assert.Equal(t, sroot+"_test/dir/"+config.MetaSuffix, p.MetaFile)
	assert.Empty(t, p.Extension)
	assert.False(t, p.Exists)
}

func TestPathInfoWithPathAndChildFile(t *testing.T) {
	path := testServer.URL + "/_test/"
	sroot := serverDefaultRoot()
	req := &httpRequest{nil, handler, "", "", "", false}

	p, err := req.pathInfo(path + "abc")
	assert.Nil(t, err)
	assert.Equal(t, path+"abc", p.URI)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/abc", p.Path)
	assert.Equal(t, path, p.ParentURI)
	assert.Equal(t, sroot+"_test/abc", p.File)
	assert.Equal(t, path+"abc"+config.ACLSuffix, p.AclURI)
	assert.Equal(t, sroot+"_test/abc"+config.ACLSuffix, p.AclFile)
	assert.Equal(t, path+"abc"+config.MetaSuffix, p.MetaURI)
	assert.Equal(t, sroot+"_test/abc"+config.MetaSuffix, p.MetaFile)
	assert.Empty(t, p.Extension)
	assert.False(t, p.Exists)
}

func TestPathInfoWithPathAndACLSuffix(t *testing.T) {
	path := testServer.URL + "/_test/"
	sroot := serverDefaultRoot()
	req := &httpRequest{nil, handler, "", "", "", false}

	p, err := req.pathInfo(path + config.ACLSuffix)
	assert.Nil(t, err)
	assert.Equal(t, path+config.ACLSuffix, p.URI)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/"+config.ACLSuffix, p.Path)
	assert.Equal(t, sroot+"_test/"+config.ACLSuffix, p.File)
	assert.Equal(t, path+config.ACLSuffix, p.AclURI)
	assert.Equal(t, sroot+"_test/"+config.ACLSuffix, p.AclFile)
	assert.Equal(t, path+config.ACLSuffix, p.MetaURI)
	assert.Equal(t, sroot+"_test/"+config.ACLSuffix, p.MetaFile)
	assert.Equal(t, config.ACLSuffix, p.Extension)
	assert.False(t, p.Exists)
}

func TestPathInfoWithPathAndMetaSuffix(t *testing.T) {
	path := testServer.URL + "/_test/"
	sroot := serverDefaultRoot()
	req := &httpRequest{nil, handler, "", "", "", false}

	p, err := req.pathInfo(path + config.MetaSuffix)
	assert.Nil(t, err)
	assert.Equal(t, path+config.MetaSuffix, p.URI)
	assert.Equal(t, testServer.URL, p.Base)
	assert.Equal(t, "_test/"+config.MetaSuffix, p.Path)
	assert.Equal(t, sroot+"_test/"+config.MetaSuffix, p.File)
	assert.Equal(t, path+config.MetaSuffix+config.ACLSuffix, p.AclURI)
	assert.Equal(t, sroot+"_test/"+config.MetaSuffix+config.ACLSuffix, p.AclFile)
	assert.Equal(t, path+config.MetaSuffix, p.MetaURI)
	assert.Equal(t, sroot+"_test/"+config.MetaSuffix, p.MetaFile)
	assert.Equal(t, config.MetaSuffix, p.Extension)
	assert.False(t, p.Exists)
}
