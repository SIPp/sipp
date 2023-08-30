FROM alpine:3.18

RUN apk add --no-cache \
  binutils \
  cmake \
  g++ \
  gcc \
  git \
  gsl-dev \
  gsl-static \
  libpcap-dev \
  make \
  ncurses-dev \
  ncurses-static

CMD cd /src && rm -f CMakeCache.txt && cmake . -DBUILD_STATIC=1 -DUSE_PCAP=1 -DUSE_GSL=1 && make 
