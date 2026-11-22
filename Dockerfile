# Standard-library Go build; the catalog and OpenAPI are embedded.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/banwords ./cmd/banwords

FROM gcr.io/distroless/static-debian12:nonroot
LABEL io.danysik.deployment-contract="coolify-v1"
COPY --from=build /out/banwords /banwords
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/banwords", "healthcheck"]
ENTRYPOINT ["/banwords"]
