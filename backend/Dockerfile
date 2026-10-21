# ---------- build stage ----------
FROM python:3.14-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc /uv /uvx /bin/

WORKDIR /project

ENV PYTHONDONTWRITEBYTECODE=1

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# ---------- runtime stage ----------
FROM python:3.14-slim AS runtime

# Disable pip, uv utilized
RUN python -m pip uninstall --yes --root-user-action=ignore pip

WORKDIR /project

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/project/.venv/bin:$PATH"

COPY --from=builder /project/.venv /project/.venv

COPY app/ ./app/
COPY alembic ./alembic/
COPY alembic.ini ./

RUN useradd -m appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
