FROM golang:1.27.4-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /iac-policy-gate ./cmd/iac-policy-gate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /iac-policy-gate /iac-policy-gate
ENTRYPOINT ["/iac-policy-gate"]
USER nonroot:nonroot
