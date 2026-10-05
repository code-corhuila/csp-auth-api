FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-api ./cmd/auth-api

FROM alpine:3.20
COPY --from=build /out/auth-api /usr/local/bin/auth-api
USER 10001
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/auth-api"]
