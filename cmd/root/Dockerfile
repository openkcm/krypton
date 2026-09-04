FROM golang:1.27 AS builder

ENV GOEXPERIMENT=runtimesecret
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /bin/krypton-root ./cmd/root

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /bin/krypton-root /bin/krypton-root

USER nonroot:nonroot
ENTRYPOINT ["/bin/krypton-root"]
