# tlsproxy in a container: a static binary on a minimal base (distroless:
# CA certificates and nothing else, running as a non-root user).
#
#   docker run -d --name tlsproxy -p 443:443 -p 127.0.0.1:9443:9443 \
#     -v /srv/tlsproxy/etc:/etc/tlsproxy -v /srv/tlsproxy/data:/var/lib/tlsproxy \
#     docker.io/wushilin/tlsproxy_go_quick:latest
#
# /etc/tlsproxy/config.toml is the configuration (it must be writable: the
# proxy replaces a plain password with its hash, and the console saves
# edits). /var/lib/tlsproxy is the working directory, so the default
# cert_path (./certs) and ca_root (./ca) are kept there. Both mounts must be
# writable by uid 65532.
#
# Built from this repository alone: dependencies are vendored, nothing is
# downloaded. Cross-compiled on the build machine for each platform.

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-mod=vendor \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/tlsproxy . && \
    mkdir -p /out/etc /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tlsproxy /usr/local/bin/tlsproxy
COPY --from=build --chown=65532:65532 /out/etc /etc/tlsproxy
COPY --from=build --chown=65532:65532 /out/data /var/lib/tlsproxy
COPY --from=build --chown=65532:65532 /src/config.toml /etc/tlsproxy/config.toml.example
WORKDIR /var/lib/tlsproxy
VOLUME ["/etc/tlsproxy", "/var/lib/tlsproxy"]
EXPOSE 443 9443
ENTRYPOINT ["/usr/local/bin/tlsproxy"]
CMD ["/etc/tlsproxy/config.toml"]
