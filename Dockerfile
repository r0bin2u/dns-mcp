FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/r0bin2u/dns-mcp"
LABEL org.opencontainers.image.description="MCP server for DNS, WHOIS (RDAP), and IP geolocation."
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["dns-mcp"]
