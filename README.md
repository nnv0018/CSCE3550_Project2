Language used: Python 3.9
Frameworks/Libraries: 
- FastAPI
- PyJWT
- cryptography
- sqlite3
Platform: macOS
Server requirement: Python virtual environment

Setup and Configuration
1. Clone repository
2. Create and activate Python virtual environment
    python3 -m venv venv
    source venv/bin/activate   # macOS/Linux
    venv\Scripts\activate      # Windows
3. Install dependencies (libraries listed above)
4. Run server
    uvicorn nnv0018App:nnv0018App --reload --port 8080