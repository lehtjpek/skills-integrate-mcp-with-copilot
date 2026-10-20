# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Students can sign up for activities
- Teachers can unregister students after signing in

## Teacher accounts

Teacher passwords are never stored in plaintext. Add or update an account
interactively from the `src` directory:

```sh
python manage_teachers.py
```

The command stores a salted PBKDF2 password hash in `teachers.json`; commit this
file when deploying teacher account changes. Set a long, random `SESSION_SECRET`
in the server environment before allowing teacher sign-in. For local HTTP
development, `SESSION_COOKIE_SECURE` defaults to `false`; the application
automatically marks the session cookie secure when the request uses HTTPS. Set
`SESSION_COOKIE_SECURE=true` when HTTPS terminates at a reverse proxy.

Students can view activities and sign up while logged out. Only logged-in
teachers can unregister students, and the API enforces this restriction
independently of the page controls.

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| GET    | `/auth/me`                                                         | Check the current teacher login                                     |
| POST   | `/auth/login`                                                      | Sign in with a teacher username and password                        |
| POST   | `/auth/logout`                                                     | End the current teacher session                                     |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up a student                                                   |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student (teacher login required)                    |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
