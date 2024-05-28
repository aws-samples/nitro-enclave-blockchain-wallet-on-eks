#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

## build
FROM go_eks_base as build
COPY . .
ARG SKIP_TEST_ARG

ARG generator_pod_folders="./cmd/key-generator_pod/... ./internal/..."
# excluded G304, since that pod is running in protected EKS environment and
# AWS_WEB_IDENTITY_TOKEN_FILE is being injected by EKS directly
RUN if [ "$SKIP_TEST_ARG" != "true" ]; then staticcheck $generator_pod_folders && \
    gosec $generator_pod_folders && \
    go test $generator_pod_folders -test.v; fi

RUN CGO_ENABLED=0 go build -ldflags="-X main.version=v0.0.1" ./cmd/key-generator_pod

## deploy image including required nitro-cli binaries
FROM nitro_eks_pod_base_image:latest AS prod
RUN yum update -y && \
    yum install openssl openssl11 gettext -y && \
    yum clean all && \
    rm -rf /var/cache/yum

RUN touch ~/.rnd

WORKDIR /app

COPY cmd/key-generator_pod/run.sh ./
COPY --from=build /app/key-generator_pod /app/key-generator_pod

CMD ["/app/run.sh"]
