FROM rust:slim-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    git \
    libssl-dev \
    perl \
    pkg-config \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/mwixnet
COPY . .
RUN cargo build --release --locked --bins

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/mwixnet/target/release/mwixnet /usr/local/bin/mwixnet
COPY --from=builder /usr/src/mwixnet/target/release/mwixnet-monitor /usr/local/bin/mwixnet-monitor
RUN mwixnet --help && mwixnet-monitor --help

WORKDIR /root/.grin
VOLUME ["/root/.grin"]

ENTRYPOINT ["mwixnet"]
CMD ["--help"]
