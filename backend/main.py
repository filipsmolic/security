from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session
import jwt
from datetime import datetime, timedelta

from database import get_db, get_raw_connection, User, Product

SECRET_KEY = "weblabos2"
ALGORITHM = "HS256"

app = FastAPI(title="Vulnerable Web App - Security Lab")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200", "http://127.0.0.1:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

    class Config:
        from_attributes = True


class ProductResponse(BaseModel):
    id: int
    name: str
    description: str
    price: float
    stock: int

    class Config:
        from_attributes = True


class SQLInjectionRequest(BaseModel):
    search_query: str
    vulnerable_mode: bool = False


class SQLInjectionResponse(BaseModel):
    results: List[dict]
    query_executed: str
    is_vulnerable: bool


class VulnerabilityToggle(BaseModel):
    sql_injection: bool = False
    access_control: bool = False


class AccessControlResponse(BaseModel):
    allowed: bool
    user_data: Optional[dict] = None
    message: str
    is_vulnerable: bool


vulnerability_settings = {
    "sql_injection": False,
    "access_control": False
}


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


@app.post("/api/toggle-vulnerabilities")
def toggle_vulnerabilities(toggle: VulnerabilityToggle):
    vulnerability_settings["sql_injection"] = toggle.sql_injection
    vulnerability_settings["access_control"] = toggle.access_control
    return {
        "message": "Vulnerability settings updated",
        "settings": vulnerability_settings
    }


@app.get("/api/auth/login")
def login():
    user_data = {
        "user_id": 2,
        "username": "john",
        "email": "john@test.com",
        "role": "user"
    }

    token = create_access_token(user_data)

    return {
        "access_token": token,
        "token_type": "Bearer",
        "user": user_data
    }


@app.post("/api/sql-injection/search", response_model=SQLInjectionResponse)
def search_users_sql_injection(request: SQLInjectionRequest):
    search_query = request.search_query
    vulnerable_mode = request.vulnerable_mode

    if vulnerable_mode:
        conn = get_raw_connection()
        cursor = conn.cursor()

        unsafe_query = f"SELECT username, email FROM users WHERE username LIKE '%{search_query}%'"

        try:
            cursor.execute(unsafe_query)
            results = cursor.fetchall()

            column_names = [description[0]
                            for description in cursor.description]

            formatted_results = []
            for row in results:
                row_dict = {}
                for i, column_name in enumerate(column_names):
                    row_dict[column_name] = row[i]
                formatted_results.append(row_dict)

            conn.close()

            return SQLInjectionResponse(
                results=formatted_results,
                query_executed=unsafe_query,
                is_vulnerable=True
            )

        except Exception as e:
            conn.close()
            return SQLInjectionResponse(
                results=[],
                query_executed=unsafe_query,
                is_vulnerable=True
            )

    else:
        conn = get_raw_connection()
        cursor = conn.cursor()

        safe_query = "SELECT username, email FROM users WHERE username LIKE %s"

        safe_param = f"%{search_query}%"

        try:
            cursor.execute(safe_query, (safe_param,))
            results = cursor.fetchall()

            column_names = [description[0]
                            for description in cursor.description]

            formatted_results = []
            for row in results:
                row_dict = {}
                for i, column_name in enumerate(column_names):
                    row_dict[column_name] = row[i]
                formatted_results.append(row_dict)

            conn.close()

            return SQLInjectionResponse(
                results=formatted_results,
                query_executed=f"{safe_query} (with parameter: '{safe_param}')",
                is_vulnerable=False,
            )

        except Exception as e:
            conn.close()
            raise HTTPException(
                status_code=500, detail="Internal server error")


class UserDataResponse(BaseModel):
    id: int
    username: str
    email: str
    password: Optional[str] = None
    role: str
    is_vulnerable: bool
    access_granted: bool


@app.get("/api/user/{user_id}")
def get_user_by_id(
    user_id: int,
    vulnerable: Optional[str] = None,
    x_vulnerable_mode: Optional[str] = Header(None, alias="X-Vulnerable-Mode"),
    authorization: Optional[str] = Header(None)
):

    current_user_id = None
    current_user_role = None
    token_data = None

    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        token_data = decode_token(token)
        if token_data:
            current_user_id = token_data.get("user_id")
            current_user_role = token_data.get("role")

    if x_vulnerable_mode:
        vulnerable_mode = (x_vulnerable_mode == "true")
    elif vulnerable:
        vulnerable_mode = (vulnerable == "true")
    else:
        vulnerable_mode = vulnerability_settings["access_control"]

    conn = get_raw_connection()
    cursor = conn.cursor()

    if vulnerable_mode:
        query = "SELECT id, username, email, password, role FROM users WHERE id = %s"

        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "id": result[0],
                "username": result[1],
                "email": result[2],
                "password": result[3],
                "role": result[4],
                "is_vulnerable": True,
                "access_granted": True,
                "message": "RANJIVO: Pristup bez autorizacije!"
            }
        else:
            raise HTTPException(status_code=404, detail="User not found")

    else:
        if not token_data or not current_user_id:
            conn.close()
            raise HTTPException(
                status_code=401,
                detail="Invalid or missing token. Valid JWT token is required to access this resource."
            )

        if user_id != current_user_id and current_user_role != "admin":
            conn.close()
            raise HTTPException(
                status_code=403,
                detail=f"Access denied."
            )

        query = "SELECT id, username, email, password, role FROM users WHERE id = %s"

        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "id": result[0],
                "username": result[1],
                "email": result[2],
                "password": result[3],
                "role": result[4],
                "is_vulnerable": False,
                "access_granted": True,
                "message": "Zaštićeno: Token Authentication radi! Pristup odobren."
            }
        else:
            raise HTTPException(status_code=404, detail="User not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
