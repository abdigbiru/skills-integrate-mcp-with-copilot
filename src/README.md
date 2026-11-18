# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- View participants without logging in
- Assigned teacher accounts can register and unregister students

## Getting Started

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. From the repository root, create each assigned teacher account:

   ```
   python -m src.auth teacher_username
   ```

   Enter and confirm a password of 12-1024 characters at the hidden prompt.
   The command creates or updates `src/teachers.json`, containing unique salts
   and PBKDF2-SHA256 password hashes, with owner-only permissions. No default
   accounts or plaintext passwords are provided. This file is ignored by Git;
   never commit account credentials. Set `TEACHER_CREDENTIALS_FILE` to use an
   alternative private location outside the static directory.

3. Run the application from the repository root:

   ```
   uvicorn src.app:app --reload
   ```

   Cookies require HTTPS by default, including when using the Codespaces HTTPS
   forwarded URL. For local HTTP development only, run:

   ```
   TEACHER_COOKIE_SECURE=false uvicorn src.app:app --reload
   ```

4. Open your browser and go to:
   - Application: http://localhost:8000 (local HTTP mode)
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## Teacher access

Use the **Teacher account** button in the header, then **Log in** to enter an
assigned username and password. Logged-in teachers see the registration form
and unregister buttons. Students still see all activities and participants, but
cannot change registrations. Both write endpoints enforce login on the server.

Sessions use random, opaque HttpOnly, SameSite=Strict cookies and expire after
eight hours. Logging out revokes the session immediately. Sessions are held in
one server process: restarting it signs everyone out; run a single worker until
a shared session store is introduced. Restart after changing/removing teacher
credentials to revoke existing sessions. Missing or malformed credentials
produce an explicit login-unavailable error; public browsing still works.

There is deliberately no account-maintenance page. Provision accounts using
the command above and distribute assigned passwords privately. This implements
issue #5's teacher-only workflow, not student self-service or Azure sign-in.

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student (teacher login required) |
| POST | `/auth/login` | Log in with a JSON body containing `username` and `password`; sets session cookie |
| GET | `/auth/session` | Get logged-in teacher username, or `null` for a visitor |
| POST | `/auth/logout` | Revoke the current session and clear its cookie |

Signup also requires a teacher session cookie; unauthenticated write requests
return HTTP 401. API clients must retain the cookie returned by login.

## Tests

From the repository root:

```
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
node --check src/static/app.js
```

Tests use temporary credentials, not real teacher accounts.

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
