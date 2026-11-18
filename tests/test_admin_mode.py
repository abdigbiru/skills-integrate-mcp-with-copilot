import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src import auth
from src.app import activities, app


class AdminModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "test-only-assigned-password"
        cls.salt = "a" * 32
        cls.record = {
            "salt": cls.salt,
            "password_hash": auth.password_hash(cls.password, cls.salt),
        }

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.credentials = Path(self.directory.name) / "teachers.json"
        self.credentials.write_text(json.dumps({"teacher": self.record}))
        env = patch.dict(os.environ, {
            "TEACHER_CREDENTIALS_FILE": str(self.credentials),
            "TEACHER_COOKIE_SECURE": "true",
        })
        env.start()
        self.addCleanup(env.stop)
        original = copy.deepcopy(activities)
        self.addCleanup(lambda: (activities.clear(), activities.update(original)))
        auth.sessions.clear()
        self.addCleanup(auth.sessions.clear)
        self.client = TestClient(app, base_url="https://testserver")
        self.addCleanup(self.client.close)

    def login(self):
        response = self.client.post("/auth/login", json={
            "username": "teacher", "password": self.password,
        })
        self.assertEqual(response.status_code, 200)
        return response

    def test_public_browsing_but_mutations_require_teacher(self):
        response = self.client.get("/activities")
        self.assertEqual(response.status_code, 200)
        self.assertIn("participants", response.json()["Chess Club"])
        self.assertIsNone(self.client.get("/auth/session").json()["username"])
        original = copy.deepcopy(activities)
        for token in (None, "forged-token"):
            headers = {"Cookie": f"{auth.COOKIE_NAME}={token}"} if token else {}
            for method, action in (("POST", "signup"), ("DELETE", "unregister")):
                response = self.client.request(
                    method, f"/activities/Chess%20Club/{action}",
                    params={"email": "michael@mergington.edu"}, headers=headers,
                )
                self.assertEqual(response.status_code, 401)
        self.assertEqual(activities, original)

    def test_bad_credentials_do_not_create_session(self):
        for username, password in (("teacher", "wrong"), ("student", self.password)):
            response = self.client.post("/auth/login", json={
                "username": username, "password": password,
            })
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["detail"], "Invalid username or password")
            self.assertNotIn(auth.COOKIE_NAME, response.cookies)
        self.assertFalse(auth.sessions)

    def test_teacher_signup_unregister_and_existing_validation(self):
        response = self.login()
        cookie = response.headers["set-cookie"].lower()
        for flag in ("httponly", "secure", "samesite=strict"):
            self.assertIn(flag, cookie)
        self.assertEqual(self.client.get("/auth/session").json()["username"], "teacher")
        params = {"email": "new-student@mergington.edu"}
        signup = "/activities/Chess%20Club/signup"
        unregister = "/activities/Chess%20Club/unregister"
        self.assertEqual(self.client.post(signup, params=params).status_code, 200)
        self.assertEqual(self.client.post(signup, params=params).status_code, 400)
        self.assertIn(params["email"], activities["Chess Club"]["participants"])
        self.assertEqual(self.client.delete(unregister, params=params).status_code, 200)
        self.assertEqual(self.client.delete(unregister, params=params).status_code, 400)
        self.assertEqual(self.client.post(
            "/activities/Unknown/signup", params=params
        ).status_code, 404)

    def test_logout_revokes_copied_cookie_and_other_sessions_are_independent(self):
        self.login()
        token = self.client.cookies.get(auth.COOKIE_NAME)
        with TestClient(app, base_url="https://testserver") as other:
            self.assertIsNone(other.get("/auth/session").json()["username"])
            self.assertEqual(self.client.post("/auth/logout").status_code, 200)
            self.assertNotIn(auth.COOKIE_NAME, self.client.cookies)
            response = other.post(
                "/activities/Chess%20Club/signup",
                params={"email": "student@mergington.edu"},
                headers={"Cookie": f"{auth.COOKIE_NAME}={token}"},
            )
            self.assertEqual(response.status_code, 401)

    def test_expired_session_cannot_mutate_registrations(self):
        self.login()
        token = self.client.cookies.get(auth.COOKIE_NAME)
        auth.sessions[token] = ("teacher", time.monotonic() - 1)
        response = self.client.delete(
            "/activities/Chess%20Club/unregister",
            params={"email": "michael@mergington.edu"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertNotIn(token, auth.sessions)

    def test_repeated_login_rotates_session(self):
        self.login()
        old_token = self.client.cookies.get(auth.COOKIE_NAME)
        self.login()
        self.assertNotEqual(old_token, self.client.cookies.get(auth.COOKIE_NAME))
        self.assertNotIn(old_token, auth.sessions)

    def test_unavailable_or_malformed_credentials_fail_explicitly(self):
        self.credentials.unlink()
        with self.assertLogs("src.auth", level="ERROR"):
            response = self.client.post("/auth/login", json={
                "username": "teacher", "password": self.password,
            })
        self.assertEqual(response.status_code, 503)
        self.credentials.write_text('{"teacher": {"password_hash": "plaintext"}}')
        with self.assertLogs("src.auth", level="ERROR"):
            response = self.client.post("/auth/login", json={
                "username": "teacher", "password": self.password,
            })
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.client.get("/activities").status_code, 200)

    def test_provisioned_account_uses_hash_and_can_log_in(self):
        with patch("src.auth.getpass.getpass", return_value=self.password):
            with patch("builtins.print"):
                auth.add_teacher("another-teacher")
        saved = json.loads(self.credentials.read_text())
        self.assertNotIn(self.password, self.credentials.read_text())
        self.assertNotEqual(saved["another-teacher"]["salt"], self.salt)
        self.assertEqual(self.credentials.stat().st_mode & 0o777, 0o600)
        response = self.client.post("/auth/login", json={
            "username": "another-teacher", "password": self.password,
        })
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
