# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.1.1
WORKDIR /src
COPY go.mod go.sum* ./
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/ipscanner-forward-auth .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=0.1.1
LABEL org.opencontainers.image.title="ipscanner-forward-auth" \
      org.opencontainers.image.description="IPScanner forward auth gate for nginx, Traefik, Caddy, HAProxy and Apache" \
      org.opencontainers.image.source="https://github.com/ipscanner/ipscanner-forward-auth" \
      org.opencontainers.image.url="https://ipscanner.io" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/ipscanner-forward-auth /ipscanner-forward-auth
USER nonroot:nonroot
ENV LISTEN=:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=2s --retries=3 \
    CMD ["/ipscanner-forward-auth", "healthcheck"]
ENTRYPOINT ["/ipscanner-forward-auth"]
