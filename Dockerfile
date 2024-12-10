FROM golang:1.23.1-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o gophKeeper_binary ./cmd/gophKeeper/main.go

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/gophKeeper_binary .

CMD ["./gophKeeper_binary"]
