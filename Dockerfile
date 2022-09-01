# Start by building the application.
FROM golang:1.18 as build
WORKDIR /go/src/app
COPY . ./
RUN go mod download
RUN go test ./...
RUN CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o /go/bin/udp-proxy ./cmd/server/

# Now copy it into our base image.
FROM gcr.io/distroless/static-debian11:debug-nonroot
USER nonroot
WORKDIR /
COPY --from=build /go/bin/udp-proxy /
ENTRYPOINT ["/udp-proxy"]
EXPOSE 53/udp