FROM golang:1.21.3

WORKDIR /server

COPY go.mod ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /docker-dns-server

EXPOSE 1234:1234

CMD ["/docker-dns-server"]
