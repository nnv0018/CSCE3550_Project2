Language used: Python 3.9
Frameworks/Libraries: (requirements-dev.txt)
- FastAPI
- PyJWT
- cryptography
- sqlite3
Platform: macOS
Server requirement: Python virtual environment

Setup and Configuration

1. Clone repository
2. Create and activate Python virtual environment
    ```
    python3 -m venv venv
    source venv/bin/activate   # macOS/Linux
    venv\Scripts\activate      # Windows
    ```
3. Install dependencies (libraries listed above)
4. Run server
    ```uvicorn nnv0018App:nnv0018App --reload --port 8080```

Running tests

Pytest configuration file: `pytest.ini`
1. Install development requirements (dev/test deps):
```bash
python3 -m pip install -r requirements-dev.txt
```
2. Run tests and show coverage for the application module only (recommended):
```bash
.venv/bin/python -m coverage run -m pytest -q && .venv/bin/python -m coverage report -m --include=nnv0018App.py
```

Alternative (one-liner using the active python / activated venv):
```bash
# using active python (after `source .venv/bin/activate`)
python -m coverage run -m pytest -q && python -m coverage report -m --include=nnv0018App.py
```

Note: The tests print an application-only coverage summary by default; if you prefer full coverage across tests and app remove the `--include` flag.