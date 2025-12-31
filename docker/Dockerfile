# Usage (from within the git repo):
#   git submodule update --init
#   docker build -t sipp -f docker/Dockerfile .

FROM alpine:3.20 AS build

ARG FULL=''

RUN apk add --no-cache \
  binutils \
  cmake \
  g++ \
  gcc \
  git \
  gsl-dev \
  gsl-static \
  help2man \
  libpcap-dev \
  make \
  ncurses-dev \
  ncurses-static \
  ninja \
  openssl-dev \
  openssl-libs-static \
  ${FULL:+linux-headers lksctp-tools-dev lksctp-tools-static}

WORKDIR /sipp
COPY CMakeLists.txt ./
COPY src src
COPY include include
COPY gtest gtest

ARG DEBUG=''
RUN --mount=type=bind,target=.git,source=.git \
  git config --global --add safe.directory /sipp && \
  cmake . -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_STATIC=1 \
    -DUSE_PCAP=1 \
    -DUSE_GSL=1 \
    ${DEBUG:+-DDEBUG=1} \
    ${FULL:+-DUSE_SCTP=1} \
  && ninja
RUN help2man --output=sipp.1 -v -v --no-info \
  --name='SIP testing tool and traffic generator' ./sipp

FROM scratch AS bin
COPY --from=build /sipp/sipp /sipp/sipp.1 /sipp/version.h /

FROM alpine:3.20
CMD ["sipp"]
COPY --from=build /sipp/sipp /usr/local/bin/sipp
