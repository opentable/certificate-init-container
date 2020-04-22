FROM docker.otenv.com/golang:1.13 as builder

RUN apt-get update && apt-get install -y git ca-certificates tzdata && update-ca-certificates
WORKDIR /certificate-init-container
COPY . .

RUN go mod download && \
  go mod verify && \
  CGO_ENABLED=0 go build

# ---------------------------------------------------------------------------------------------
FROM scratch

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /certificate-init-container/certificate-init-container /certificate-init-container

ENTRYPOINT ["/certificate-init-container"]
