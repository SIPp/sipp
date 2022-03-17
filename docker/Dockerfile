FROM alpine:3.10

RUN apk add --no-cache binutils make cmake gcc g++ ncurses-static libpcap-dev ncurses-dev gsl-dev

CMD cd /src && rm -f CMakeCache.txt && cmake . -DBUILD_STATIC=1 -DUSE_PCAP=1 -DUSE_GSL=1 && make 
