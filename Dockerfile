FROM golang:latest AS builder
RUN mkdir /app
WORKDIR /app/
COPY go.mod go.sum ./
RUN go mod download
RUN go install github.com/goreleaser/goreleaser@v0.181.1
COPY . .
RUN goreleaser build --config .goreleaser-linux.yml --rm-dist --snapshot


FROM alpine:latest
WORKDIR /
COPY --from=builder /app/dist/checkmate_linux_amd64  .
COPY --from=builder /app/cors_config.yaml  .
RUN mkdir -p /var/lib/checkmate
EXPOSE 17283
CMD [ "/checkmate", "api", "--port", "17283", "--serve-git-service", "--data-path", "/var/lib/checkmate" ]
