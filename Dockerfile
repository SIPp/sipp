ARG ALPINE_VERSION=3.13

FROM alpine:${ALPINE_VERSION} as builder

LABEL maintainer="Napadailo Yaroslav <experimental.rabbit.1986@gmail.com>"
LABEL desription="SIPp image based on forked repository"
LABEL vcs-type="git"
LABEL vcs-url="https://github.com/man1207/sipp.git"

RUN apk add --no-cache \
  git \
  binutils \
  make \
  cmake \
  gcc \
  g++ \
  ncurses-dev \
  ncurses-static \
  libpcap-dev \
  gsl-dev \
  gsl-static \
  openssl-dev \
  openssl-libs-static \
  linux-headers \
  lksctp-tools-dev \
  lksctp-tools-static

COPY . /src

RUN cd /src \
  && git submodule update --init \
  && rm -f CMakeCache.txt \
  && cmake . -DBUILD_STATIC=1 -DUSE_PCAP=1 -DUSE_GSL=1 -DUSE_SSL=1 -DUSE_SCTP=1 \
  && make

FROM alpine:${ALPINE_VERSION}

COPY --from=builder /src/sipp /usr/local/bin/sipp

RUN apk update

EXPOSE 5060

ENTRYPOINT ["sipp"]
