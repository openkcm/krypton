#!/usr/bin/env bash

for dir in "$@"; do
  protoc \
    --proto_path="$dir" \
    --go_out=. \
    --go_opt=module=github.com/openkcm/krypton \
    --go-grpc_out=. \
    --go-grpc_opt=module=github.com/openkcm/krypton \
    "$dir"/*.proto
done
