FROM golang:rc-stretch

COPY ./ /src
WORKDIR /src
RUN go install github.com/coolbet/login/cmd/login

EXPOSE 8080

ENTRYPOINT login
