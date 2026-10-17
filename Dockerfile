FROM python:3.12-slim

WORKDIR /opt/aegis
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

EXPOSE 8765
ENTRYPOINT ["aegis"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765"]
