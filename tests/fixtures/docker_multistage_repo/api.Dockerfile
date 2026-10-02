FROM node:20 AS deps
RUN npm ci

FROM python:3.12-slim AS tools
RUN pip install awscli

FROM deps
COPY --from=tools /usr/local/bin/aws /usr/local/bin/aws
ARG NPM_TOKEN=fixture-npm-token
USER root
HEALTHCHECK CMD curl -f http://localhost:3000/health
