FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS gosu-builder

ARG TARGETARCH
ARG TARGETOS

# MariaDB's gosu 1.19 binary was built with vulnerable Go 1.24.6. Rebuild the
# same audited commit with the project's patched Go toolchain.
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH GOOS=$TARGETOS \
    go install -ldflags="-s -w" \
    github.com/tianon/gosu@6456aaa0f3c854d199d0f037f068eb97515b7513

FROM mariadb:11@sha256:efb4959ef2c835cd735dbc388eb9ad6aab0c78dd64febcd51bc17481111890c4

COPY --from=gosu-builder --chmod=0755 /go/bin/gosu /usr/local/bin/gosu
