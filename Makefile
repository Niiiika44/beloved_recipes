APP_PORT=8000

help:
	@echo "Available targets: up, down, migrate, run, test, lint."

up:
	docker compose -f infra/docker-compose.yml up -d --wait
down:
	docker compose -f infra/docker-compose.yml down
migrate:
	docker compose -f infra/docker-compose.yml up postgres -d --wait
	uv run  --directory backend alembic upgrade head
run:
	uv run --directory backend uvicorn app.main:app --host 127.0.0.1 --port $(APP_PORT)
test:
	uv run --directory backend pytest -q tests --cov
lint:
	uv run --directory backend ruff check .
	uv run --directory backend ruff format --check
	uv run --directory backend mypy app tests

.PHONY: up down migrate run test lint
