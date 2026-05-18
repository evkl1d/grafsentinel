FROM python:3.12-slim

WORKDIR /app
COPY grafsentinel.py ./

RUN useradd --create-home --uid 1000 scanner
USER scanner

ENTRYPOINT ["python", "grafsentinel.py"]
CMD ["--help"]
