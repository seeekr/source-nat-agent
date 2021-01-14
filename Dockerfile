FROM golang:alpine AS build

WORKDIR /code

COPY go.mod /code
COPY go.sum /code
COPY main.go /code

RUN GOOS=linux GOARCH=amd64 go build -o source-nat-agent

FROM alpine:latest
RUN apk add -q iptables
COPY --from=build /code/source-nat-agent .

CMD ["./source-nat-agent"]
