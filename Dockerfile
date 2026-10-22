FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /mailreportd .
RUN mkdir -p /state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mailreportd /mailreportd
# Matches storage.path in config.example.yaml, owned by the nonroot user so a
# fresh named volume is writable.
COPY --from=build --chown=65532:65532 /state /var/lib/mailreportd
VOLUME /var/lib/mailreportd
EXPOSE 8088 9188
ENTRYPOINT ["/mailreportd"]
CMD ["-config", "/etc/mailreportd/config.yaml"]
