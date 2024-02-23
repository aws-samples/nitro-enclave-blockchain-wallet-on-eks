#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

## build
FROM go_lambda_base as build
COPY . .
ARG SKIP_TEST_ARG

ARG lambda_folders="./cmd/lambda/... ./internal/..."

# exclude TLS InsecureSkipVerify set true warning - pod is generating self signed certificate which needs to be
# imported to Lambda for validation - no transport in place right now
RUN if [ "$SKIP_TEST_ARG" != "true" ]; then staticcheck $lambda_folders && \
    gosec $lambda_folders && \
    go test $lambda_folders -test.v; fi

RUN go build -o /main ./cmd/lambda

# copy artifacts to a clean image
FROM public.ecr.aws/lambda/provided:al2 AS prod
COPY --from=build /main /main
ENTRYPOINT [ "/main" ]