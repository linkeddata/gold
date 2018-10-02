# gold

[![](https://img.shields.io/badge/project-Solid-7C4DFF.svg?style=flat-square)](https://github.com/solid/solid)
[![Join the chat at https://gitter.im/linkeddata/gold](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/linkeddata/gold?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`gold` is a reference Linked Data Platform server for the
**[Solid platform](https://github.com/solid/solid-spec)**.

Written in Go, based on
[initial work done by William Waites](https://bitbucket.org/ww/gold).

[![Build Status](https://travis-ci.org/linkeddata/gold.svg?branch=master)](https://travis-ci.org/linkeddata/gold)

## Installing

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

1. Setup Go + dependencies:

  * **Mac OS X**: `brew install go raptor libmagic`
  * **Ubuntu**: `sudo apt-get install golang-go libraptor2-dev libmagic-dev`

2. Set the `GOPATH` variable (required by Go):

  ```bash
  mkdir ~/go
  export GOPATH=~/go
  ```

  (Optionally consider adding `export GOPATH=~/go` to your `.bashrc` or profile).

3. Check that you have the required Go version (**Go 1.4 or later**):

  ```
  go version
  ```

  If you don't, please [install](http://golang.org/doc/install) a more recent
  version.

4. Use the `go get` command to install the server and all the dependencies:

    go get github.com/linkeddata/gold/server

5. (Optional) Install extra dependencies used by the tests:

    go get github.com/stretchr/testify/assert

## Running the Server

**IMPORTANT**: Among other things, `gold` is a web server. Please consider
running it as a regular user instead of root. Since gold treats all files
equally, and even though uploaded files are not made executable, it will not
prevent clients from uploading malicious shell scripts.

Pay attention to the data root parameter, `-root`. By default, it will serve
files from its current directory (so, for example, if you installed it from
Github, its data root will be `$GOPATH/src/github.com/linkeddata/gold/`).
Otherwise, make sure to pass it a dedicated data directory to serve, either
using a command-line parameter or the [config file](#configuration).
Something like: `-root=/var/www/data/` or `-root=~/data/`.

1. If you installed it from package via `go get`, you can run it by:

  ```
  $GOPATH/bin/server -http=":8080" -https=":8443" -debug
  ```

2. When developing locally, you can `cd` into the repo cloned by `go get`:

  ```
  cd $GOPATH/src/github.com/linkeddata/gold
  ```

  And launch the server by:

  ```
  go run server/*.go -http=":8080" -https=":8443" -debug -boltPath=/tmp/bolt.db
  ```

  Alternatively, you can compile and run it from the source dir in one command:

  ```
  go run $GOPATH/src/github.com/linkeddata/gold/server/*.go -http=":8080" -https=":8443" \
    -root=/home/user/data/ -debug -boltPath=/tmp/bolt.db
  ```

## Configuration

You can use the provided `gold.conf-example` file to create your own
configuration file, and specify it with the `-conf` parameter.

```bash
cd $GOPATH/src/github.com/linkeddata/gold/
cp gold.conf-example server/gold.conf

# edit the configuration file
nano server/gold.conf

# pass the config file when launching the gold server
$GOPATH/bin/server -conf=$GOPATH/src/github.com/linkeddata/gold/server/gold.conf
```

To see a list of available options:

    ~/go/bin/server -help

Some important options and defaults:

* `-conf` - Optional path to a config file.

* `-debug` - Outputs config parameters and extra logging. Default: `false`.

* `-root` - Specifies the data root directory which `gold` will be serving.
  Default: `.` (so, likely to be `$GOPATH/src/github.com/linkeddata/gold/`).

* `-http` - HTTP port on which the server listens. For local development,
  the default HTTP port, `80`, is likely to be reserved, so pass in an
  alternative. Default: `":80"`. Example: `-http=":8080"`.

* `-https` - HTTPS port on which the server listens. For local development,
  the default HTTPS port, `443`, is likely to be reserved, so pass in an
  alternative. Default: `":443"`. Example: `-https=":8443"`.

## Testing
To run the unit tests (assuming you've installed `assert` via
`go get github.com/stretchr/testify/assert`):

```
make test
```

## Notes

* HOWTO : [Get an example X.509 cert](https://gist.github.com/melvincarvalho/e14753a7137d02d756f19299fed292b4)
* HOWTO : [Login after getting a 401](https://gist.github.com/melvincarvalho/72eaff2fbf1b51a805846320e0bff0cc)
* HOWTO : [Recover an account](https://gist.github.com/melvincarvalho/bcc04e1529dd3a4509892346109b1d37)

## License
[MIT](http://joe.mit-license.org/)
