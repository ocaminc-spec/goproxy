# Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
# GoProxy DNS – container image (linux/amd64)
# Build from the repo root:  docker build -f docker/Dockerfile -t goproxy:2.8.2 --build-arg VERSION=2.8.2 .
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG VERSION=2.7.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION} -X main.Vendor=Ocam" -o /out/goproxy . \
 && apk add --no-cache libcap \
 && setcap cap_net_bind_service=+ep /out/goproxy

FROM alpine:3.22
# ca-certificates: DoH upstreams; tzdata: TZ=America/New_York; busybox nslookup is used by the healthcheck
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 1000 goproxy && adduser -S -D -H -u 1000 -G goproxy goproxy \
 && mkdir -p /data && chown 1000:1000 /data
COPY --from=build /out/goproxy /usr/local/bin/goproxy
USER 1000:1000
VOLUME ["/data"]
EXPOSE 53/udp 53/tcp 8080/tcp
ENV TZ=America/New_York
# v2.5.0: container mode (also auto-detected from /.dockerenv): no in-app self-update / rollback / restart
ENV GOPROXY_CONTAINER=true
# Container mode: data in /data, self-update off (update = pull new image), no PTR to router by default overridable
ENTRYPOINT ["/usr/local/bin/goproxy", "-data-dir", "/data", "-update-dir", "off"]
CMD ["-dns-addr", ":53", "-http-addr", ":8080"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD nslookup -timeout=3 www.google.com 127.0.0.1 >/dev/null 2>&1 || exit 1
