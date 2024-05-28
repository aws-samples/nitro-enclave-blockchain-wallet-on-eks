#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

## build
FROM go_eks_base as build
COPY . .
ARG SKIP_TEST_ARG

# make tests skipable for cross platform compile tests to save significant time
# excluded G304, since that pod is running in protected EKS environment and AWS_WEB_IDENTITY_TOKEN_FILE \
# is being injected by EKS directly
ARG signing_pod_folders="./cmd/signing_pod/... ./internal/..."
RUN if [ "$SKIP_TEST_ARG" != "true" ]; then staticcheck $signing_pod_folders && \
    gosec $signing_pod_folders && \
    go test $signing_pod_folders -test.v; fi

RUN CGO_ENABLED=0 go build -ldflags="-X main.version=v0.0.1" ./cmd/signing_pod

## deploy image including required nitro-cli binaries
FROM nitro_eks_pod_base_image:latest as prod
RUN yum update -y && \
    yum install openssl openssl11 -y && \
    yum clean all && \
    rm -rf /var/cache/yum
RUN touch ~/.rnd

WORKDIR /app

COPY cmd/signing_pod/run.sh ./
COPY --from=build /app/signing_pod /app/signing_pod


CMD ["/app/run.sh"]
