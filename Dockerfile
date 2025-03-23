FROM golang:latest AS builder
RUN mkdir /app
WORKDIR /app/
COPY go.mod go.sum ./
RUN go mod download
RUN go install github.com/goreleaser/goreleaser@latest
COPY . .
RUN goreleaser build --config .goreleaser-linux.yaml --clean --snapshot


#base ruby for asciidoctor-pdf
FROM ruby:slim 
RUN mkdir -p /var/lib/checkmate 
RUN mkdir -p /app/plugins
WORKDIR /app
COPY --from=builder /app/dist/checkmate_linux_amd64_v1  /app/checkmate
COPY --from=builder /app/plugins/* /app/plugins/
COPY --from=builder /app/cors_config.yaml  .
# install asciidoctor-pdf for PDF reports
RUN apt update -y && apt upgrade -y && apt install ruby -y
RUN gem install rghost && gem install rouge && gem install text-hyphen 
RUN gem install asciidoctor-pdf
# start CheckMate API service
# EXPOSE 17283
# CMD [ "/app/checkmate", "api", "--port", "17283", "--serve-git-service", "--data-path", "/var/lib/checkmate" ]
# Stage 1: Build the Go binary

# Set a non-root user for security
USER 65532:65532

# Run the binary
ENTRYPOINT ["/app/checkmate"]
