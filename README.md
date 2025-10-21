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

Running test (test is written with the help of Copilot)
*Pytest configuration file: pytest.ini
1. Install requirements
```pip3 install -r requirements.txt```
2. Run this command from project's root directory
```.venv/bin/python -m coverage run -m pytest -q && .venv/bin/python -m coverage report -m```

Note: The gradebot and test coverage screen shot is included in the repository.  