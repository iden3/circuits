# Build circom container that will use into github/workflows

# Build circom
FROM rust:1.59.0 as circom-instaler

WORKDIR /

RUN git clone https://github.com/iden3/circom.git && \
    cd circom && \
    cargo build --release && \
    cargo install --path circom

# Print version of rust
RUN strip -g /usr/local/cargo/bin/circom \
  && echo "CARGO_VERSION='$(cargo --version)'" >> /etc/image-info \
  && echo "RUST_VERSION='$(rustc --version)'" >> /etc/image-info

# Install node for run tests
FROM node:16.14.2

COPY --from=circom-instaler /usr/local/cargo/bin/circom /bin/
