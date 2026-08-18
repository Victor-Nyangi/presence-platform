FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
# go.sum is generated on first `go mod tidy`; see README.
RUN go mod download
COPY . .
# Static binary so the runtime image can be distroless/scratch-like.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /gateway ./cmd/gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gateway /gateway
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/gateway"]
