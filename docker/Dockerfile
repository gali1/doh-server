FROM ubuntu:22.04
LABEL maintainer="JK"

SHELL ["/bin/sh", "-x", "-c"]
ENV SERIAL 2

ENV CFLAGS=-Ofast
ENV BUILD_DEPS   curl make build-essential git libevent-dev libexpat1-dev autoconf file libssl-dev byacc pkg-config
ENV RUNTIME_DEPS bash util-linux coreutils findutils grep libssl3 ldnsutils libevent-2.1 expat ca-certificates runit runit-helper jed logrotate

RUN apt-get update; apt-get -qy dist-upgrade; apt-get -qy clean && \
    apt-get install -qy --no-install-recommends $RUNTIME_DEPS && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

RUN update-ca-certificates 2> /dev/null || true

WORKDIR /tmp

ENV RUSTFLAGS "-C link-arg=-s"

RUN apt-get update && apt-get install -qy --no-install-recommends $BUILD_DEPS && \
    curl -sSf https://sh.rustup.rs | bash -s -- -y --default-toolchain stable && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    echo "Building DoH Proxy from source" && \
    git clone https://github.com/junkurihara/doh-server doh-server && \
    cd doh-server && git checkout multiple_relays && \
    cargo build --release --no-default-features --features=odoh-proxy&& \
    mkdir -p /opt/doh-proxy/sbin && \
    mv /tmp/doh-server/target/release/doh-proxy /opt/doh-proxy/sbin/ && \
    strip --strip-all /opt/doh-proxy/sbin/doh-proxy && \
    apt-get -qy purge $BUILD_DEPS && apt-get -qy autoremove && \
    rm -fr ~/.cargo ~/.rustup && \
    rm -fr /tmp/* /var/tmp/* /var/cache/apt/* /var/lib/apt/lists/* /var/log/apt/* /var/log/*.log

COPY doh-proxy.sh /
COPY entrypoint.sh /

RUN chmod 755 /doh-proxy.sh

RUN chmod 755 /entrypoint.sh

EXPOSE 3000/udp 3000/tcp

CMD ["/entrypoint.sh"]

ENTRYPOINT ["/entrypoint.sh"]
