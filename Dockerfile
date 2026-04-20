FROM golang:alpine as builder

WORKDIR /src
COPY . /src
RUN go install github.com/coolbet/login/cmd/login

FROM alpine:latest
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=builder /go/bin/login /app/
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=5s --retries=10 CMD curl --fail http://localhost:8080/users || exit 1
ENTRYPOINT ["/app/login"]