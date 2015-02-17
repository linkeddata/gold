.PHONY: test cover
test:
	go get golang.org/x/tools/cmd/cover
	go test -cover -v .

bench:
	@go test -bench . -benchmem

cover:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

travis-sudo:
	apt-get update -qq
	apt-get install -qq libmagic-dev librdf0-dev
	dpkg -P librdf0-dev librasqal3-dev libraptor2-dev librdf0 libraptor2-0 librasqal3 rasqal-utils redland-utils raptor2-utils
	make -f `pwd`/Makefile -C /usr/local/src travis-src

travis-src:
	wget http://download.librdf.org/source/raptor2-2.0.15.tar.gz http://download.librdf.org/source/rasqal-0.9.33.tar.gz http://download.librdf.org/source/redland-1.0.17.tar.gz;
	for x in *.tar.gz; do tar -xzf $$x; done
	cd raptor2-*; ./configure --prefix=/usr --exec-prefix=/usr; make install
	cd rasqal-*; ./configure --prefix=/usr --exec-prefix=/usr; make install
	cd redland-*; ./configure --prefix=/usr --exec-prefix=/usr; make install
