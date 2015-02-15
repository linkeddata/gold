FROM golang

RUN \
  apt-get update -y && \
  apt-get install -y libraptor2-dev libmagic-dev && \
  rm -rf /var/lib/apt/lists/* && \
  go get -u -x github.com/linkeddata/gold/server

EXPOSE 443
VOLUME ["/data"]
CMD ["server","-https=:443", "-root=/data/"]
