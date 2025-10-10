import time
#import uuid
import base64
import jwt
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from fastapi import FastAPI 
from fastapi import Request
from fastapi import FastAPI, Request, Response
nnv0018App = FastAPI()

DB_FileName = "totally_not_my_privateKeys.db"
def create_db():
    conn = sqlite3.connect(DB_FileName)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
              """ )
    conn.commit()
    conn.close()

def sent_key_to_db(private_key, exp):
    #PKCS1
    pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format= serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )
    conn = sqlite3.connect(DB_FileName)
    c = conn.cursor()
    c.execute("INSERT INTO keys (key, exp) VALUES (?,?)", (pem, exp))
    conn.commit()
    kid = c.lastrowid #get the assigned kid
    conn.close()

def get_key_from_db(expired=False):
    conn = sqlite3.connect(DB_FileName)
    c = conn.cursor()
    now = int (time.time())
    if expired:
        c.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (now,))
        #select a key that is expired now or less
    else :
        c.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (now,))
        #select a key that is expire in one hour or more
    #fetch that sigle row contain the key
    row = c.fetchone()
    if not row: #no key fetch
        return None
    kid, pem, exp = row
    private_key = serialization.load_pem_private_key(pem, password=None)
    return {"kid": kid,
            "private_key": private_key,
            "exp" : exp
    }

def generate_and_store_key():
    #generate and store key that expire one hour later or more
    now = int(time.time())
    pk_active= rsa.generate_private_key(
        public_exponent=65537, #for security & performance
        key_size=2048, #strength of the key
    )
    kid_active = sent_key_to_db(pk_active, now + 3600)
    #exp_active = now + 3600
    #sent_key_to_db(kid_active, pk_active, exp_active)
    print(f"Created active key with kid={kid_active}")
    
    #generate and store key that expire now or less (10 seconds ago)
    pk_expired = rsa.generate_private_key(
        public_exponent=65537, #for security & performance
        key_size=2048, #strength of the key
    )
    kid_expired = sent_key_to_db(pk_expired, now - 10)
    #exp_expired = now - 10
    #sent_key_to_db(kid_expired, pk_expired, exp_expired)
    print(f"Created active key with kid={kid_expired}")

"""
def generateKey():
    #generate new RSA rpivate key 
    private_key = rsa.generate_private_key(
        public_exponent=65537, #for security & performance
        key_size=2048, #strength of the key
    )
    #get the corresponding public key from the private key
    public_key = private_key.public_key();

    #associate a Key ID (kid) and expiry timestamp with each key
    kid = str(uuid.uuid4())
    expiry = int (time.time()) + 3600 #1hour

    return {"kid": kid,
            "expiry": expiry,
            "private_key": private_key,
            "public_key" : public_key
    }
print(generateKey())
active_key = generateKey()
expired_key = generateKey()
expired_key["expiry"]= int(time.time()) -10 
#10 seconds a go from the current time -> expired
keys = [active_key, expired_key]
    """
@nnv0018App.on_event("startup")
def startUp_Event():
    create_db()
    generate_and_store_key()
@nnv0018App.get("/")
def root():
    return {"message": "JWKS Server is running"}

@nnv0018App.get("/.well-known/jwks.json") #return all valid public keys
def getJkws():
    conn = sqlite3.connect(DB_FileName)
    c = conn.cursor()
    now = int(time.time())
    c.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    rows = c.fetchall()
    conn.close()
    jwksKeys = []
    for kid, pem in rows:
        private_key = serialization.load_pem_private_key(pem, password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        
        """
        if key["expiry"] > int (time.time()):
            public_key = key["public_key"]
            public_numbers = public_key.public_numbers()
        """
        mod = public_numbers.n
        exp = public_numbers.e
        
        mod_b64 = base64.urlsafe_b64encode(mod.to_bytes((mod.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
        exp_b64 = base64.urlsafe_b64encode(exp.to_bytes((exp.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(kid),
            "n": mod_b64,
            "e": exp_b64
            }
        jwksKeys.append(jwk)
    return {"keys" : jwksKeys}    

@nnv0018App.post("/auth")
def auth(request: Request): #chooses expired or valid keys dynamically
    """
    status = request.query_params.get("expired")

    if status == "true": #"expired" query parameter is present
        signingKey = expired_key
    else:
        signingKey = active_key
    token_expiry = int(time.time()) + 900 #15minutes
    payload = {
        "sub" : "user321",
        "iat" : int(time.time()),
        "exp" : token_expiry
    }
    if status == "true":
        payload["exp"] = signingKey["expiry"]
    """
    expiredParam = request.query_params.get("expired")
    expired = expiredParam == "true"
    signingKey = get_key_from_db(expired=expired)
    if not signingKey: #error check
        return {"Error, key was not loaded!"}, 404
    token_expiry = int (time.time()) + 900 #15 min
    payload = {
        "sub" : "user321",
        "iat" : int(time.time()),
        "exp" : token_expiry
    }
    headers = {
        "kid" : str(signingKey["kid"])
    }
    #convert the signed private key to PEM
    pem_private = signingKey["private_key"].private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )
    token = jwt.encode(
        payload, pem_private, algorithm="RS256", headers = headers
    )
    #print(f"Generated Token: {token}") FIX TOKEN error

    return Response(content=token, media_type="text/plain")