FROM rust:alpine as base
RUN apk update \
    && apk add \
        git \
        gcc \
        g++ \
        openssl \
        openssl-dev \
        pkgconfig

COPY . /src

RUN rustup update 1.64 && rustup default 1.64

RUN cd /src && \
    RUSTFLAGS="-C target-feature=-crt-static" cargo build --release --example otp

FROM alpine as tool

RUN apk update && \
    apk add \
        libgcc \
        pcsc-lite-dev

COPY --from=base /src/target/release/examples/otp /usr/local/bin
ENTRYPOINT [ "otp" ]
