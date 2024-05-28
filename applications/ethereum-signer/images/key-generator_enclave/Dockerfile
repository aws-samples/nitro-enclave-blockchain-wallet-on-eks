#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

## build
FROM go_eks_base as build
COPY . .
ARG generator_enclave_folders='./cmd/key-generator_enclave/... ./internal/...'

ARG SKIP_TEST_ARG

RUN if [ "$SKIP_TEST_ARG" != "true" ]; then staticcheck $generator_enclave_folders && \
    gosec $generator_enclave_folders && \
    go test $generator_enclave_folders -test.v; fi

RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -ldflags="-X main.version=v0.0.1" ./cmd/key-generator_enclave

## deploy image
FROM alpine:latest AS prod
RUN apk update && \
    apk add ca-certificates iproute2 && \
    rm -rf /var/cache/apk/*

ARG REGION_ARG
ENV REGION=$REGION_ARG

ARG LOG_LEVEL_ARG
ENV LOG_LEVEL=$LOG_LEVEL_ARG

ARG VSOCK_BASE_PORT_ARG
ENV PORT=$VSOCK_BASE_PORT_ARG

WORKDIR /app

# viproxy for outbound communication
COPY ./third_party/proxy/proxy /app
COPY ./cmd/key-generator_enclave/run.sh /app
COPY --from=build /app/key-generator_enclave /app/key-generator_enclave

CMD ["sh", "/app/run.sh"]
