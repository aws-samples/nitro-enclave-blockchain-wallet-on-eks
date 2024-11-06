#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

## build
FROM go_eks_base as build
COPY . .
ARG SKIP_TEST_ARG

ARG signing_enclave_folders="./cmd/signing_enclave/... ./internal/..."

RUN if [ "$SKIP_TEST_ARG" != "true" ]; then staticcheck $signing_enclave_folders && \
    gosec $signing_enclave_folders && \
    go test $signing_enclave_folders -test.v; fi

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -ldflags="-X main.version=v0.0.1" ./cmd/signing_enclave

## deploy image
FROM debian:bookworm-slim AS prod
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    apt-get clean && \
    apt-get autoremove --yes && \
    rm -rf /var/lib/apt/lists/*

ARG REGION_ARG
ENV REGION=$REGION_ARG

ARG LOG_LEVEL_ARG
ENV LOG_LEVEL=$LOG_LEVEL_ARG

ARG VSOCK_BASE_PORT_ARG
ENV PORT=$VSOCK_BASE_PORT_ARG

WORKDIR /app

COPY --from=build /app/signing_enclave /app/signing_enclave

CMD ["/app/signing_enclave"]
