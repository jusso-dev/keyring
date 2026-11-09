# syntax=docker/dockerfile:1
#
# Keyring container image.
#
# Build stage: static musl binary from the pinned Rust toolchain, with
# Cargo.lock enforced. Templates (Askama) and static files are compiled
# into the binary, so nothing else is copied across.
#
# Runtime stage: distroless static (nonroot). No shell, no package
# manager, CA certificates included for TLS to Entra ID and Azure.
# Runs as UID 65532 and works with a read-only root filesystem and no
# Linux capabilities.
#
# Both base images are pinned by digest. Dependabot proposes updates.

FROM rust:1.99.1-alpine3.22@sha256:9a744dc47d1ac2a7d17fc3cedfc8b4928b1696dfcba3274ab25bfb40988a9ff0 AS build
# Use the toolchain already in the pinned image. rust-toolchain.toml isn't
# copied: it lists rustfmt and clippy, which would make rustup download
# them, and the release build needs neither. CI checks the image's Rust
# version matches rust-toolchain.toml.
ENV RUSTUP_TOOLCHAIN=1.99.1
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY static ./static
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/keyring /keyring

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="Keyring" \
      org.opencontainers.image.description="A plain-English web front end for Azure Key Vault that acts as the signed-in user" \
      org.opencontainers.image.source="https://github.com/jusso-dev/keyring" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build --chmod=0555 /keyring /keyring
# 65532 is distroless's nonroot user. Numeric so Kubernetes' runAsNonRoot
# check can verify it.
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/keyring"]
