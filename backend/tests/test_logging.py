import json
import logging
from collections.abc import Iterator
from typing import Any

import pytest
import structlog

from app.core.config import get_settings
from app.core.logging import configure_logging

UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    saved_root = (list(root.handlers), root.level)
    saved = {
        name: (
            list(logging.getLogger(name).handlers),
            logging.getLogger(name).propagate,
            logging.getLogger(name).level,
        )
        for name in UVICORN_LOGGERS
    }

    yield

    root.handlers[:] = saved_root[0]
    root.setLevel(saved_root[1])
    for name, (handlers, propagate, level) in saved.items():
        logger = logging.getLogger(name)
        logger.handlers[:] = handlers
        logger.propagate = propagate
        logger.setLevel(level)
    structlog.reset_defaults()
    get_settings.cache_clear()


def _configure(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    configure_logging()


def _json_lines(captured: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in captured.splitlines() if line.startswith("{")]


def test_root_gets_single_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    handlers = logging.getLogger().handlers

    assert len(handlers) == 1
    assert isinstance(handlers[0].formatter, structlog.stdlib.ProcessorFormatter)


def test_uvicorn_loggers_are_rerouted(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        assert logger.handlers == []
        assert logger.propagate is True


def test_uvicorn_access_is_silenced(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    logger = logging.getLogger("uvicorn.access")

    assert logger.handlers == []
    assert logger.propagate is False


def test_access_logger_produces_no_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    logging.getLogger("uvicorn.access").info("должно исчезнуть")

    assert capsys.readouterr().out == ""


def test_level_comes_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(monkeypatch, APP__ENV="ci", APP__LOG_LEVEL="WARNING")

    assert logging.getLogger().level == logging.WARNING


def test_level_filters_records(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="ci", APP__LOG_LEVEL="WARNING")

    structlog.get_logger("t").info("не должно пройти")
    structlog.get_logger("t").warning("должно пройти")

    events = [record["event"] for record in _json_lines(capsys.readouterr().out)]
    assert events == ["должно пройти"]


def test_ci_renders_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    structlog.get_logger("t").info("событие", order_id=7)

    records = _json_lines(capsys.readouterr().out)
    assert len(records) == 1
    assert records[0]["event"] == "событие"
    assert records[0]["order_id"] == 7
    assert records[0]["level"] == "info"
    assert records[0]["timestamp"].endswith("Z")


def test_cyrillic_is_not_escaped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    structlog.get_logger("t").info("заказ создан")

    out = capsys.readouterr().out
    assert "заказ создан" in out
    assert "\\u0437" not in out


def test_local_renders_human_readable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="local")

    structlog.get_logger("t").info("событие")

    out = capsys.readouterr().out
    assert "событие" in out
    assert _json_lines(out) == []


def test_internal_meta_keys_are_stripped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    structlog.get_logger("t").info("событие")

    record = _json_lines(capsys.readouterr().out)[0]
    assert "_record" not in record
    assert "_from_structlog" not in record


def test_stdlib_records_carry_context(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="ci")
    structlog.contextvars.bind_contextvars(request_id="abc-123")

    structlog.get_logger("t").info("своя запись")
    logging.getLogger("sqlalchemy.engine").warning("чужая запись")

    records = _json_lines(capsys.readouterr().out)
    assert [record["event"] for record in records] == ["своя запись", "чужая запись"]
    assert {record["request_id"] for record in records} == {"abc-123"}
    assert [record["level"] for record in records] == ["info", "warning"]


def test_exception_info_is_rendered(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="ci")

    try:
        raise RuntimeError("взрыв")
    except RuntimeError:
        structlog.get_logger("t").exception("упало")

    record = _json_lines(capsys.readouterr().out)[0]
    assert "RuntimeError: взрыв" in record["exception"]


def test_renderer_follows_env_after_reconfiguration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(monkeypatch, APP__ENV="local")
    structlog.get_logger("t").info("первое")
    assert _json_lines(capsys.readouterr().out) == []

    _configure(monkeypatch, APP__ENV="ci")
    structlog.get_logger("t").info("второе")

    records = _json_lines(capsys.readouterr().out)
    assert [record["event"] for record in records] == ["второе"]
