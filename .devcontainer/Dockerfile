FROM mcr.microsoft.com/devcontainers/cpp:1-debian-12

RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt/lists \
    apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    help2man \
    libgsl-dev \
    libpcap-dev \
    libssl-dev \
    libsctp-dev
