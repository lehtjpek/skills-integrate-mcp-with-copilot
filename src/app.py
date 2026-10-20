"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=current_dir / "static"), name="static")

TEACHERS_FILE = current_dir / "teachers.json"
SESSION_COOKIE = "teacher_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 310_000

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128, pattern="^[^:]+$")
    password: str = Field(max_length=1024)


def _session_secret() -> bytes:
    secret = os.getenv("SESSION_SECRET")
    if not secret or len(secret.encode("utf-8")) < 32:
        raise HTTPException(
            status_code=503,
            detail="Teacher login is not configured. Set a SESSION_SECRET of at least 32 bytes.",
        )
    return secret.encode("utf-8")


def _load_teachers() -> dict[str, dict[str, str]]:
    with TEACHERS_FILE.open(encoding="utf-8") as teachers_file:
        data = json.load(teachers_file)

    teachers = data.get("teachers")
    if not isinstance(teachers, list):
        raise ValueError("teachers.json must contain a 'teachers' list")
    result = {}
    for teacher in teachers:
        if (
            not isinstance(teacher, dict)
            or not isinstance(teacher.get("username"), str)
            or not isinstance(teacher.get("salt"), str)
            or not isinstance(teacher.get("password_hash"), str)
        ):
            raise ValueError("Each teacher entry must include username, salt, and password_hash")
        if teacher["username"] in result:
            raise ValueError(f"Duplicate teacher username: {teacher['username']}")
        result[teacher["username"]] = teacher
    return result


def _password_matches(password: str, teacher: dict[str, str]) -> bool:
    try:
        salt = bytes.fromhex(teacher["salt"])
        expected_hash = bytes.fromhex(teacher["password_hash"])
    except ValueError:
        return False
    if len(salt) != 16 or len(expected_hash) != 32:
        return False
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def _create_session(username: str) -> str:
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{username}:{expires_at}".encode("utf-8")
    signature = hmac.new(_session_secret(), payload, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload + b":" + signature).decode("ascii")
    return token.rstrip("=")


def _session_username(token: str | None) -> str | None:
    if not token or len(token) > 512 or not os.getenv("SESSION_SECRET"):
        return None
    try:
        decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        payload, expires_bytes, signature = decoded.rsplit(b":", 2)
        username = payload.decode("utf-8")
        expires_at = int(expires_bytes)
    except (ValueError, UnicodeDecodeError):
        return None

    expected_signature = hmac.new(
        _session_secret(), payload + b":" + expires_bytes, hashlib.sha256
    ).digest()
    if expires_at < int(time.time()) or not hmac.compare_digest(
        signature, expected_signature
    ):
        return None
    return username


def _require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        raise HTTPException(status_code=403, detail="Origin header is required")
    parsed_origin = urlsplit(origin)
    if (
        parsed_origin.scheme != request.url.scheme
        or parsed_origin.netloc != request.url.netloc
    ):
        raise HTTPException(status_code=403, detail="Cross-origin request denied")


def get_current_teacher(request: Request) -> str | None:
    return _session_username(request.cookies.get(SESSION_COOKIE))


def require_teacher(teacher: str | None = Depends(get_current_teacher)) -> str:
    if teacher is None:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return teacher


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/auth/me")
def current_user(teacher: str | None = Depends(get_current_teacher)):
    return {"authenticated": teacher is not None, "username": teacher}


@app.post("/auth/login")
def login(credentials: LoginRequest, request: Request, response: Response):
    _require_same_origin(request)
    teachers = _load_teachers()
    teacher = teachers.get(credentials.username)
    if teacher is None or not _password_matches(credentials.password, teacher):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE,
        value=_create_session(credentials.username),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=(
            os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
            or request.url.scheme == "https"
        ),
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "username": credentials.username}


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    _teacher: str = Depends(require_teacher),
):
    _require_same_origin(request)
    response.delete_cookie(key=SESSION_COOKIE, path="/", httponly=True, samesite="strict")
    return {"authenticated": False}


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: str,
    request: Request,
    _teacher: str = Depends(require_teacher),
):
    """Unregister a student from an activity"""
    _require_same_origin(request)
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
