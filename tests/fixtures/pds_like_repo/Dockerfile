FROM node:18-alpine

WORKDIR /app

# Missing USER directive — container runs as root by default.
# Missing HEALTHCHECK.

# Fetch and execute a remote installer during image build.
RUN curl -sSL https://install.example.com/setup.sh | bash

COPY --chown=root:root ./app /app

# Fetch remote resource, no checksum.
ADD https://cdn.example.com/artifact.tar.gz /tmp/

EXPOSE 3000
EXPOSE 3001/tcp

CMD ["node", "server.js"]
