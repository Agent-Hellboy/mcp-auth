FROM golang:1.25.13 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mcp-auth-server ./cmd/auth-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mcp-auth-server /mcp-auth-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/mcp-auth-server"]
