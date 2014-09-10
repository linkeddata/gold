FROM dockerfile/go

RUN \
  apt-get update -y && \
  apt-get install -y libraptor2-dev libmagic-dev && \
  rm -rf /var/lib/apt/lists/* && \
  go get github.com/linkeddata/gold/server && \
  mkdir /gold-data/

EXPOSE 443
CMD ["bin/server","-bind=:443", "-root=/gold-data/"]
