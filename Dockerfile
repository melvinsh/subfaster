# Build
FROM golang:1.24-alpine AS build-env
RUN apk add build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/subfaster

# Release
FROM alpine:latest
RUN apk upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /app/subfaster /usr/local/bin/

ENTRYPOINT ["subfaster"]
