# tlsproxy in a container: a static binary on a minimal base (distroless:
# CA certificates and nothing else, running as a non-root user).
#
#   docker run -d --name tlsproxy -p 443:443 \
#     -e CONSOLE_DOMAIN=admin.example.com -e CONSOLE_PASSWORD='...' \
#     -v /srv/tlsproxy/etc:/etc/tlsproxy -v /srv/tlsproxy/data:/var/lib/tlsproxy \
#     docker.io/wushilin/tlsproxy_go_quick:latest
#
# /etc/tlsproxy/config.yaml is the configuration. The web console is on by
# default, on port 443 with its own domain: CONSOLE_DOMAIN and
# CONSOLE_PASSWORD are required (or pass /etc/tlsproxy/config.yaml
# -noconsole as the command). The folder must be writable: the console saves
# edits there. /var/lib/tlsproxy is the working directory, so the default
# cert_root (./certs: the CAs and the ACME certificates) is kept there. Both mounts must be
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
LABEL org.opencontainers.image.source="https://github.com/wushilin/tlsproxy_go_quick" \
      org.opencontainers.image.description="TLS SNI proxy: pass-through or terminate, ACME and local CAs, web console"
COPY --from=build /out/tlsproxy /usr/local/bin/tlsproxy
COPY --from=build --chown=65532:65532 /out/etc /etc/tlsproxy
COPY --from=build --chown=65532:65532 /out/data /var/lib/tlsproxy
COPY --from=build --chown=65532:65532 /src/config.yaml /etc/tlsproxy/config.yaml.example
WORKDIR /var/lib/tlsproxy
VOLUME ["/etc/tlsproxy", "/var/lib/tlsproxy"]
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/tlsproxy"]
CMD ["/etc/tlsproxy/config.yaml"]
