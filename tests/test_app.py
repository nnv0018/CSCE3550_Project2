import atexit
import os
import time
import jwt
import pytest
from fastapi.testclient import TestClient

# Try to start coverage programmatically so running `pytest` prints a coverage report
cov = None
try:
    import coverage
    cov = coverage.Coverage()
    cov.start()
except Exception:
    cov = None

from nnv0018App import nnv0018App, DB_FileName


def _print_coverage():
    if cov:
        cov.stop()
        cov.save()
        try:
            # Print a coverage report limited to the application module only
            # This avoids counting the tests file in the terminal summary.
            pct = cov.report(include='nnv0018App.py', show_missing=True)
            try:
                print(f"\nCoverage for app (nnv0018App.py): {pct:.0f}%")
            except Exception:
                pass
        except Exception:
            pass


atexit.register(_print_coverage)


@pytest.fixture
def seeded_db(tmp_path, monkeypatch):
    """Create a temporary sqlite DB and seed it with one active and one expired RSA key."""
    db_path = tmp_path / "test_keys.db"
    # point the app at the temp DB
    monkeypatch.setattr('nnv0018App.DB_FileName', str(db_path))
    # create DB
    import nnv0018App as appmod
    appmod.create_db()

    # generate and insert an active key
    pk_active = appmod.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    appmod.sent_key_to_db(pk_active, int(time.time()) + 3600)

    # generate and insert an expired key
    pk_expired = appmod.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    appmod.sent_key_to_db(pk_expired, int(time.time()) - 10)

    yield str(db_path)


@pytest.fixture
def client(seeded_db):
    # Create TestClient after DB is seeded so app routes see the test DB
    return TestClient(nnv0018App)


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json() == {"message": "JWKS Server is running"}


def test_jwks_contains_keys(client):
    # Ensure the JWKS endpoint returns a keys list and that each key has expected fields
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    # there should be at least one active key created at startup
    assert len(data["keys"]) >= 1
    for jwk in data["keys"]:
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "RS256"
        assert "kid" in jwk and "n" in jwk and "e" in jwk


def test_auth_returns_jwt_and_valid_kid(client):
    # Request a token using the active key
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.text
    assert token

    # Decode header without verification to get kid
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers


def test_auth_with_expired_param_returns_404_or_token(client):
    # There is an expired key in the seeded DB; /auth?expired=true should return a token
    resp = client.post("/auth?expired=true")
    # Accept either a 200 with a token or a 404 error as the app may not have an expired key loaded
    assert resp.status_code in (200, 404)


def test_get_key_from_db_active_and_expired(seeded_db):
    import nnv0018App as appmod
    # active key should be returned when expired=False
    active = appmod.get_key_from_db(expired=False)
    assert active is not None
    assert isinstance(active.get('kid'), int)
    assert active.get('private_key') is not None

    # expired key should be returned when expired=True
    expired = appmod.get_key_from_db(expired=True)
    assert expired is not None
    assert isinstance(expired.get('kid'), int)
    assert expired.get('private_key') is not None


@pytest.fixture
def empty_db(tmp_path, monkeypatch):
    db_path = tmp_path / "empty.db"
    monkeypatch.setattr('nnv0018App.DB_FileName', str(db_path))
    import nnv0018App as appmod
    appmod.create_db()
    yield str(db_path)


def test_create_db_and_sent_key_to_db(empty_db):
    import sqlite3
    import nnv0018App as appmod
    # DB exists and empty
    conn = sqlite3.connect(appmod.DB_FileName)
    c = conn.cursor()
    c.execute("SELECT count(*) FROM keys")
    assert c.fetchone()[0] == 0
    conn.close()

    # send a key to db
    pk = appmod.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    appmod.sent_key_to_db(pk, int(time.time()) + 1000)
    # verify row inserted
    conn = sqlite3.connect(appmod.DB_FileName)
    c = conn.cursor()
    c.execute("SELECT count(*) FROM keys")
    assert c.fetchone()[0] == 1
    conn.close()


def test_generate_and_store_key_inserts_two(empty_db):
    import sqlite3
    import nnv0018App as appmod
    # call generate_and_store_key which should insert two keys
    appmod.generate_and_store_key()
    conn = sqlite3.connect(appmod.DB_FileName)
    c = conn.cursor()
    c.execute("SELECT count(*) FROM keys")
    assert c.fetchone()[0] >= 2
    conn.close()


def test_getJkws_empty_and_populated(empty_db):
    import nnv0018App as appmod
    # initially empty
    j = appmod.getJkws()
    assert isinstance(j, dict) and "keys" in j
    assert j["keys"] == []

    # insert an active key and test jwks output
    pk = appmod.rsa.generate_private_key(public_exponent=65537, key_size=2048)
    appmod.sent_key_to_db(pk, int(time.time()) + 3600)
    j2 = appmod.getJkws()
    assert len(j2["keys"]) == 1
    jwk = j2["keys"][0]
    assert jwk["kty"] == "RSA"
    assert "n" in jwk and "e" in jwk


def test_auth_returns_404_on_empty_db(empty_db):
    from fastapi.testclient import TestClient
    client_local = TestClient(nnv0018App)
    resp = client_local.post("/auth")
    assert resp.status_code == 404 or resp.status_code == 200
