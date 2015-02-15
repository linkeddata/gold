# gold

[![Join the chat at https://gitter.im/linkeddata/gold](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/linkeddata/gold?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Linked Data server for Go

[![Build Status](https://travis-ci.org/linkeddata/gold.png)](https://travis-ci.org/linkeddata/gold)

## Install

### From docker repository:

    sudo docker pull linkeddata/gold

    sudo docker run -p ip:port:443 linkeddata/gold

Replace `ip` and `port` with your host computer's IP address and port number.

To check the status of the container, type:

    sudo docker ps

`IMPORTANT`: if you want to mount a host directory into the container, you can use the -v parameter:

    sudo docker run -p ip:port:443 -v /home/user/data:/data linkeddata/gold

This will mount the host directory, `/home/user/data`, into the container as the `/data/` directory. Doing this will allow you to reuse the data directory without worrying about persistence inside the container.


### From Github:

Setup Go + dependencies:

    # on OSX eg.
    brew install go raptor libmagic

    # on Ubuntu eg.
    sudo apt-get install golang-go libraptor2-dev libmagic-dev 

    mkdir ~/go; export GOPATH=~/go

Use the `go get` command to install the server and all the dependencies:

    go get github.com/linkeddata/gold/
    
Optionally, you can install some extra dependencies used by the tests:

    go get github.com/drewolson/testflight
    go get github.com/stretchr/testify/assert

Run the server:

    cd ~/go/src/github.com/linkeddata/gold/server && go install
    ~/go/bin/server -https=":443" -root="/home/user/data/" -debug
    
Alternatively, you can compile and run it from the source dir in one command:
    
    go run ~/go/src/github.com/linkeddata/gold/server/daemon.go -https=":443" -root="/home/user/data/" -debug

To see a list of avialable options:

    ~/go/bin/server -help

## License

[MIT](http://joe.mit-license.org/)
