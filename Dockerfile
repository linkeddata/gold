FROM golang

RUN \
  apt-get update -y && \
  apt-get install -y libraptor2-dev libmagic-dev && \
  rm -rf /var/lib/apt/lists/* && \
  go get -u -x github.com/linkeddata/gold/server

EXPOSE 443
EXPOSE 80
VOLUME ["/data", "/config"]
ADD gold.conf-example /tmp/
RUN mv /tmp/gold.conf-example /config/
CMD ["server", "-conf=/config/gold.conf", "-https=:443","-http=:80", "-root=/data/", "-debug"]
