FROM golang:latest AS builder
RUN mkdir /app
WORKDIR /app/
COPY go.mod go.sum ./
RUN go mod download
RUN go install github.com/goreleaser/goreleaser@latest
COPY . .
RUN goreleaser build --config .goreleaser-linux.yml --rm-dist --snapshot


#base ruby for asciidoctor-pdf
FROM ruby:slim 
WORKDIR /
RUN mkdir -p /var/lib/checkmate
COPY --from=builder /app/dist/checkmate_linux_amd64_v1  .
COPY --from=builder /app/cors_config.yaml  .
# install asciidoctor-pdf for PDF reports
RUN apt update -y && apt upgrade -y && apt install ruby -y
RUN gem install rghost && gem install rouge && gem install text-hyphen 
RUN gem install asciidoctor-pdf
# start CheckMate API service
EXPOSE 17283
CMD [ "/checkmate", "api", "--port", "17283", "--serve-git-service", "--data-path", "/var/lib/checkmate" ]
