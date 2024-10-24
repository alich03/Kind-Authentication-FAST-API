from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt 
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
import requests
# Route to test the current user endpoint
from sqlalchemy.orm import Session
# Import the User model and get_db dependency
from database import User, get_db

KINDE_ISSUER_URL = "https://frontenddevelopment.kinde.com"

# Define your Pydantic model for user info
# class UserInfo(BaseModel):
#     email: str
#     family_name: str
#     given_name: str
#     id: str
#     name: str
# Token authentication scheme
bearer_scheme = HTTPBearer()

def get_public_key(kid):
    # The URL to the JWKs endpoint (replace with the actual endpoint)
    jwks_url = KINDE_ISSUER_URL+"/.well-known/jwks.json"
    response = requests.get(jwks_url)
    jwks = response.json()

    # Find the key with the matching key ID (kid)
    for jwk in jwks['keys']:
        if jwk['kid'] == kid:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            return public_key
    raise Exception(f"Public key with kid {kid} not found")


# Function to decode JWT (replace this with your actual decoding logic)
def decode_jwt(token: str) -> Optional[dict]:
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header['kid']
        public_key = get_public_key(kid)
        # Replace with your actual decoding key and algorithm
        decoded_data = jwt.decode(token, public_key, algorithms=['RS256'],options={"verify_aud": False})
        # print("data",decoded_data)
        return decoded_data
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except Exception as e:
        return f"Error decoding JWT: {e}"
# Function to get the current user from the token


app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    'localhost',
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/register")
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme), db: Session = Depends(get_db)):
    token = credentials.credentials
    print(f"Token received: yes")
    decoded_data = decode_jwt(token)

    if isinstance(decoded_data, dict):
        # Check if the user already exists in the database

        try:
            encoded_email = decoded_data['email']
        except:
            encoded_email = decoded_data['ext_provider']["claims"]["email"]

        user = db.query(User).filter(User.email == encoded_email).first()
        if user:
            msg = "User Alreay Exist."
        if not user:
            # If the user doesn't exist, create a new user entry
            user = User(
                auth_id=decoded_data['sub'],
                email= encoded_email,
                full_name=decoded_data['name'],
                first_name=decoded_data['given_name'],
                last_name=decoded_data['family_name'],
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            msg = "User saved successfully"

        # Return the user data
        data =  {
            "auth_id": user.auth_id,
            "email": user.email,
            "full name": user.full_name,
            "first_name": user.first_name,
            "last_name": user.last_name,
            
        }
        
        return {
            "data": data,
            "message": msg
        }
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8000)
