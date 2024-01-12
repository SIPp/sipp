# Usage (from within the git repo):
#   git submodule update --init
#   docker build -t sipp -f docker/Dockerfile .

FROM alpine:3.19 AS build

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
  ncurses-static \
  ninja

WORKDIR /sipp
COPY CMakeLists.txt ./
COPY src src
COPY include include
COPY gtest gtest
RUN --mount=type=bind,target=.git,source=.git \
  cmake . -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_STATIC=1 \
    -DUSE_PCAP=1 \
    -DUSE_GSL=1
RUN ninja

FROM scratch AS bin
COPY --from=build /sipp/sipp /sipp

FROM alpine:3.19
CMD ["sipp"]
COPY --from=build /sipp/sipp /usr/local/bin/sipp
