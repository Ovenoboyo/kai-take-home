FROM golang:1.23-alpine AS builder

RUN apk add --no-cache make gcc musl-dev sqlite-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY Makefile .

RUN make build

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/build/server .
CMD ["/app/server"]
