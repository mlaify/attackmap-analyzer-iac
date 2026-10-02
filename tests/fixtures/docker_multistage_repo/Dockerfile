# Pinned builder that drops privileges; the shipped stage does not.
FROM --platform=$BUILDPLATFORM golang:1.22@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS builder
USER nobody
WORKDIR /src
COPY . .
RUN go build -o /tmp/app .

FROM scratch
COPY --from=builder /tmp/app /app
ENV AWS_SECRET_ACCESS_KEY=fixture-not-a-real-key \
    LOG_LEVEL=info
ENV DB_PASSWORD_FILE=/run/secrets/db
ARG BUILD_TOKEN
HEALTHCHECK CMD ["/app", "health"]
ENTRYPOINT ["/app"]
