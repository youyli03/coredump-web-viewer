"""The HTTP layer, tested as HTTP.

Every other suite stops at a boundary this one crosses: `tests/unit/` proves the MI records are parsed,
`tests/gdb/` proves the transport reads a real core, and until now nothing proved the thing a user actually
talks to — a status code, an error body, the session lifecycle.

Three rules keep these tests honest, all of them from `docs/api.md`:

* **assert promises, not key sets.** A test that pins whatever a dictionary happens to contain this week
  passes forever and proves nothing;
* **build the scenario, do not hope for it.** `create_app` is handed its configuration and its paths, so the
  offline half needs neither a core nor a gdb, and nothing here writes into the checkout;
* **helpers are fixtures, not imports.** Every one of these files is a `conftest.py` sibling, and a root
  `conftest.py` already exists — `from conftest import …` would be resolved by pytest's import mode rather
  than by intent.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib

import pytest
from fastapi.testclient import TestClient

from config import CONFIG
from web.app import create_app

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tmp" / "practice"

GDB = pathlib.Path(
    os.environ.get("CDWV_GDB") or ROOT / "tmp" / "arm-toolchain" / "bin" / "aarch64-none-linux-gnu-gdb"
)
"""The cross gdb, resolved exactly as `tests/gdb/test_mi_transport.py` resolves it: `CDWV_GDB` first, then the
Arm-style name under the download location `AGENTS.md` sanctions. A host-native gdb is not enough — it reads
the core's executable and refuses the core itself."""


def _offline_config(**overrides):
    """A configuration with no gdb behind it, for the tests that must not need one.

    `gdb_path` deliberately does not exist: it makes a session fail *at load*, which is how 409 and
    `state: failed` are reached without a core, and it keeps the suite from ever spawning a debugger by
    accident.
    """
    return dataclasses.replace(
        CONFIG,
        gdb_path="/nonexistent-gdb-for-tests",
        max_limit=16,
        max_sessions=1,
        command_timeout_s=1.0,
        probe_timeout_s=1.0,
        **overrides,
    )


def _core_for(program: str) -> pathlib.Path | None:
    cores = sorted(BUNDLE.glob(f"{program}.*.core"))
    return cores[-1] if cores else None


def _open_session(client: TestClient, **body) -> dict:
    """Open a session and wait for it to stop loading, through the API's own `?wait=`.

    Returning while `state` is `loading` is how a test ends up asserting against an empty summary and calling
    it a failure of the code under test.
    """
    created = client.post("/api/sessions", json=body)
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]
    polled = client.get(f"/api/sessions/{session_id}", params={"wait": 30})
    assert polled.status_code == 200, polled.text
    return polled.json()


def _live_client(tmp_path: pathlib.Path, **overrides) -> TestClient:
    """An app pointed at the real bundle and the real cross gdb, with its state file still in `tmp_path`.

    The bundle is the *real* one on purpose — these are the tests that must run against a real aarch64 core —
    but nothing here writes into the checkout.
    """
    if _core_for("crash_target") is None or not GDB.exists():
        pytest.skip(f"the live half needs the practice bundle and a cross gdb: {BUNDLE} and {GDB}")
    settings = {"gdb_path": str(GDB), "max_limit": 4096, **overrides}
    app = create_app(
        dataclasses.replace(CONFIG, **settings),
        root=ROOT,
        state_path=tmp_path,
        bundle=BUNDLE,
    )
    return TestClient(app)


# --- fixtures ----------------------------------------------------------------------------------------- #
@pytest.fixture
def offline(tmp_path: pathlib.Path):
    """An app of our own: temporary state file, empty bundle, no gdb.

    `with TestClient(...)` matters: the shutdown half of the lifespan runs on exit, and that is where the
    "kill every child gdb" promise lives (§6 of the architecture).
    """
    (tmp_path / "bundle").mkdir()
    app = create_app(_offline_config(), root=tmp_path, state_path=tmp_path, bundle=tmp_path / "bundle")
    with TestClient(app) as client:
        yield client


@pytest.fixture
def not_a_core(tmp_path: pathlib.Path) -> pathlib.Path:
    """A file that is not a core, which is what a mistyped path usually is.

    Real, readable, and completely wrong: the failure path has to survive a plausible-looking mistake rather
    than only an obviously empty string.
    """
    path = tmp_path / "not-a-core"
    path.write_text("this is not a core dump\n", encoding="utf-8")
    return path


@pytest.fixture
def live(tmp_path: pathlib.Path):
    with _live_client(tmp_path) as client:
        yield client


@pytest.fixture
def live_tight(tmp_path: pathlib.Path):
    """The same real core and gdb with the byte ceiling turned down to 16.

    The offline app cannot reach the length refusal: a session that never loaded answers 409 before it ever
    looks at the argument. So the only honest way to test the ceiling is a *ready* session whose ceiling is
    small — which is what the injected configuration is for.
    """
    with _live_client(tmp_path, max_limit=16) as client:
        yield client


@pytest.fixture
def open_session():
    """`open_session(client, sample=…)` — the API's own wait, wrapped so tests cannot forget it."""
    return _open_session


@pytest.fixture
def bundle() -> pathlib.Path:
    return BUNDLE


@pytest.fixture
def core_for():
    """`core_for("smash_ra")` — the core that belongs to one practice program, or None."""
    return _core_for
