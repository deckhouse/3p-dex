ARG BASE_IMAGE=alpine

FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.9.0@sha256:c64defb9ed5a91eacb37f96ccc3d4cd72521c4bd18d5442905b95e2226b0e707 AS xx

FROM --platform=$BUILDPLATFORM golang:1.25.6-alpine3.22@sha256:ad295fcdadc2f7f9bd9a966fef904f7e2be08cb78074e857b6a1369eb0eaa00a AS builder

COPY --from=xx / /

RUN apk add --update alpine-sdk ca-certificates openssl clang lld

ARG TARGETPLATFORM

RUN xx-apk --update add musl-dev gcc

# lld has issues building static binaries for ppc so prefer ld for it
RUN [ "$(xx-info arch)" != "ppc64le" ] || XX_CC_PREFER_LINKER=ld xx-clang --setup-target-triple

RUN xx-go --wrap

WORKDIR /usr/local/src/dex

ARG GOPROXY

ENV CGO_ENABLED=1

COPY go.mod go.sum ./
COPY api/v2/go.mod api/v2/go.sum ./api/v2/
COPY examples/go.mod examples/go.sum ./examples/
RUN go mod download

COPY . .

# Propagate Dex version from build args to the build environment
ARG VERSION
RUN make bin/example-app

RUN xx-verify /usr/local/src/dex/bin/example-app

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS stager-alpine

RUN mkdir -p /etc/ssl/certs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

FROM gcr.io/distroless/base-debian12:nonroot AS stager-distroless

FROM stager-${BASE_IMAGE} AS stager

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS runtime-alpine

FROM gcr.io/distroless/base-debian12:nonroot AS runtime-distroless

FROM runtime-${BASE_IMAGE} AS runtime

COPY --from=stager /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ 2>/dev/null || true

COPY --from=builder --chown=65532:65532 /usr/local/src/dex/bin/example-app /app/example-app

EXPOSE 5555

ENTRYPOINT ["/app/example-app"]


