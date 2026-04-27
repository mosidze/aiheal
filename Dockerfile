FROM golang:alpine

# Stage 1: Build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o login github.com/coolbet/login/cmd/login

# Stage 2: Runtime
FROM alpine:latest
RUN addgroup -S app && adduser -S app -G app
USER app:app
WORKDIR /app
COPY --from=0 /src/login .
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=3 CMD curl --fail http://localhost:8080/health || exit 1
CMD ["login"]