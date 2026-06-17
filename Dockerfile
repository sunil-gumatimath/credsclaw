FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/auditor

# Install dependencies first (layer caching)
COPY requirements.txt pyproject.toml README.md ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

# Copy the package and install it so `python -m auditor` works from any directory
COPY auditor/ ./auditor/
RUN python -m pip install .

RUN addgroup --system app && adduser --system --ingroup app app

RUN mkdir -p /work \
    && chown -R app:app /opt/auditor /work

USER app
WORKDIR /work

ENTRYPOINT ["python", "-m", "auditor"]
CMD ["--help"]
