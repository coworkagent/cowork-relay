FROM rust:1.98.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY vendor ./vendor
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN groupadd --gid 10001 cowork-relay && useradd --uid 10001 --gid 10001 --no-create-home cowork-relay \
    && mkdir /data && chown 10001:10001 /data && chmod 0700 /data
COPY --from=build /src/target/release/cowork-relay /usr/local/bin/cowork-relay
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8443/tcp
ENTRYPOINT ["/usr/local/bin/cowork-relay", "--data-dir", "/data"]
CMD ["serve"]
