"""Interactively add or update a teacher account without storing plaintext passwords."""

import getpass
import hashlib
import json
import secrets
from pathlib import Path

from app import PASSWORD_HASH_ITERATIONS, TEACHERS_FILE


def main():
    username = input("Teacher username: ").strip()
    if not username or ":" in username:
        raise SystemExit("Username must be non-empty and must not contain ':'")

    password = getpass.getpass("Teacher password (at least 12 characters): ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")

    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )

    if TEACHERS_FILE.exists():
        with TEACHERS_FILE.open(encoding="utf-8") as teachers_file:
            data = json.load(teachers_file)
    else:
        data = {"teachers": []}

    teachers = data.get("teachers")
    if not isinstance(teachers, list):
        raise ValueError("teachers.json must contain a 'teachers' list")
    teachers[:] = [
        teacher
        for teacher in teachers
        if not isinstance(teacher, dict) or teacher.get("username") != username
    ]
    teachers.append(
        {
            "username": username,
            "salt": salt.hex(),
            "password_hash": password_hash.hex(),
        }
    )
    TEACHERS_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Updated teacher account {username!r} in {Path(TEACHERS_FILE).name}.")


if __name__ == "__main__":
    main()
