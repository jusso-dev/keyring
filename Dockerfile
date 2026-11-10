# syntax=docker/dockerfile:1.27@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
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
# The build frontend (syntax line) and both base images are pinned by
# digest. The frontend is needed for RUN --mount and COPY --chmod.
# Dependabot proposes updates for the base images. To move the frontend,
# take the digest from `docker buildx imagetools inspect docker/dockerfile:<tag>`.
#
# VERSION and VCS_REF tie an image to the commit it was built from. CI
# passes them; for your own builds:
#   docker build --build-arg VERSION=0.1.0 --build-arg VCS_REF=$(git rev-parse HEAD) .

FROM rust:1.99.1-alpine3.22@sha256:9a744dc47d1ac2a7d17fc3cedfc8b4928b1696dfcba3274ab25bfb40988a9ff0 AS build
# Use the toolchain already in the pinned image (its rustup default).
# rust-toolchain.toml isn't copied: it lists rustfmt and clippy, which would
# make rustup download them, and the release build needs neither. CI checks
# the image's Rust version matches rust-toolchain.toml, so the version is
# written in two places only, and Dependabot moves both together.
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
COPY --from=build --chmod=0555 /keyring /keyring
# After the copy, so a new commit only changes these small layers.
ARG VERSION=unknown
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Keyring" \
      org.opencontainers.image.description="A plain-English web front end for Azure Key Vault that acts as the signed-in user" \
      org.opencontainers.image.source="https://github.com/jusso-dev/keyring" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"
# For the binary to report at start. Version and commit only, nothing else.
ENV KEYRING_VERSION="${VERSION}" \
    KEYRING_VCS_REF="${VCS_REF}"
# 65532 is distroless's nonroot user. Numeric so Kubernetes' runAsNonRoot
# check can verify it.
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/keyring"]
