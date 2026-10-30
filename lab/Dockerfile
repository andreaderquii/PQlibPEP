FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
RUN cargo build --locked --release --features pep-role-lab --bin pqpep-lab
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/pqpep-lab /usr/local/bin/pqpep-lab
COPY lab/make-certs.sh /app/make-certs.sh
RUN chmod 755 /app/make-certs.sh
ENTRYPOINT ["pqpep-lab"]
