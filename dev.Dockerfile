FROM alpine:latest

RUN apk add -q iptables

COPY ./source-nat-agent-linux ./source-nat-agent

CMD ["./source-nat-agent"]