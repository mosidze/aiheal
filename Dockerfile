FROM golang:alpine AS build

WORKDIR /src
COPY . /src
RUN go install github.com/coolbet/login/cmd/login

FROM alpine:latest
RUN addgroup -S app && adduser -S app -G app
USER app
WORKDIR /app
COPY --from=build /go/bin/login /app/
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=5s --retries=10 --start-period=5s CMD curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/users || exit 1
ENTRYPOINT ["/app/login"]