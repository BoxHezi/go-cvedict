FROM golang:1.24 AS builder
WORKDIR /code
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o cvedict .

FROM golang:1.24-alpine
COPY --from=builder /code/cvedict .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
