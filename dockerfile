FROM golang:1.24

WORKDIR /app

COPY . .

RUN go mod tidy

RUN go build -o auth-service ./cmd

EXPOSE 5002

CMD ["./auth-service"]
