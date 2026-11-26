# Builds the official SIG-Network Gateway API conformance test binary so it can run
# inside a kind cluster (reaching ClusterIP Gateway Services directly with zero MetalLB flakes).
FROM golang:1.23-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY conformance_test.go ./
RUN CGO_ENABLED=0 go test -c -o /usr/local/bin/shunt-gateway-conformance .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /usr/local/bin/shunt-gateway-conformance /usr/local/bin/shunt-gateway-conformance
ENTRYPOINT ["/usr/local/bin/shunt-gateway-conformance"]
