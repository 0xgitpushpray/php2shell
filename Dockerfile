# Small static image for remote checks:
#   docker run --rm ghcr.io/0xgitpushpray/php2shell check example.com
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /php2shell ./cmd/php2shell

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /php2shell /php2shell
ENTRYPOINT ["/php2shell"]
