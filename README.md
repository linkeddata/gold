# gold

Linked Data server for Go

[![Build Status](https://travis-ci.org/linkeddata/gold.png)](https://travis-ci.org/linkeddata/gold)

## Install

Setup Go + dependencies:

    # on OSX eg.
    brew install go raptor libmagic

    # on Ubuntu eg.
    sudo apt-get install golang-go libraptor2-dev libmagic-dev 

    mkdir ~/go; export GOPATH=~/go

Use the `go get` command:

    go get github.com/linkeddata/gold/server
    
Optionally, you can install some extra dependencies used by the tests:

    go get github.com/drewolson/testflight
    go get github.com/stretchr/testify/assert

Run the server:

    $GOPATH/bin/server -help

## License

[MIT](http://joe.mit-license.org/)
