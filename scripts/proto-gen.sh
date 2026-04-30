#!/usr/bin/env bash

protoc \
  --proto_path="$1" \
  --go_out=. \
  --go_opt=module=github.com/openkcm/krypton \
  --go-grpc_out=. \
  --go-grpc_opt=module=github.com/openkcm/krypton \
  "$1"/*.proto
