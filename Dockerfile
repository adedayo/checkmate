FROM golang:latest AS builder

RUN mkdir /app
WORKDIR /app/

COPY go.mod go.sum ./
RUN go mod download

RUN go install github.com/goreleaser/goreleaser@v0.181.1


COPY . .

# RUN CGO_ENABLED=0 GOOS=linux go build -o checkmate -trimpath -a -ldflags '-w -extldflags "-static"'
RUN goreleaser build --config .goreleaser-linux.yml --rm-dist --snapshot


FROM alpine:latest

WORKDIR /
COPY --from=builder /app/dist/checkmate_linux_amd64  .

EXPOSE 17283

CMD [ "/checkmate", "api", "--port", "17283" ]
