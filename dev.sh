#!/bin/sh

# using chokidar from npm as convenient file watcher
chokidar '**/*.yaml' '**/*.go' -c "./build.sh && docker build . -f dev.Dockerfile -t source-nat-agent && docker tag source-nat-agent localhost:55001/source-nat-agent && docker push localhost:55001/source-nat-agent && kubectl apply -f agent.yaml && kubectl -n source-nat-agent delete po --all && echo done"
