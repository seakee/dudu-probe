FROM golang:1.24.5-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=1.0.0
ARG COMMIT=dev
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/seakee/dudu-probe/internal/version.Version=${VERSION} -X github.com/seakee/dudu-probe/internal/version.Commit=${COMMIT} -X github.com/seakee/dudu-probe/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/dudu-probe ./cmd/dudu-probe

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/dudu-probe /usr/local/bin/dudu-probe

ENV HOST_PROC=/host/proc \
    HOST_SYS=/host/sys \
    HOST_ETC=/host/etc \
    HOST_ROOT=/host/root

ENTRYPOINT ["/usr/local/bin/dudu-probe"]
