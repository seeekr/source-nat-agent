#!/bin/sh -e

# assuming this needs to run on linux/amd64

GOOS=linux GOARCH=amd64 go build -o ./source-nat-agent-linux
