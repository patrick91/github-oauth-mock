from urllib.parse import parse_qs, parse_qsl, urlparse

import pytest
from inline_snapshot import snapshot
from fastapi.testclient import TestClient

from github_oauth_mock.app import app
from github_oauth_mock.auth import FAIL_CLIENT_ID


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def authorize(
    client: TestClient,
    *,
    client_id: str = "test-client",
    redirect_uri: str = "https://example.com/callback",
    email: str = "test@example.com",
    scope: str = "user:email",
    state: str = "state-123",
) -> str:
    response = client.post(
        "/login/oauth/authorize",
        data={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "email": email,
            "scope": scope,
            "state": state,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    return response.headers["location"]


def exchange(
    client: TestClient,
    code: str,
    *,
    client_id: str = "test-client",
    accept: str | None = None,
):
    headers = {}
    if accept:
        headers["accept"] = accept
    return client.post(
        "/login/oauth/access_token",
        data={"client_id": client_id, "code": code},
        headers=headers,
    )


def extract_code(location: str) -> str:
    query = parse_qs(urlparse(location).query)
    return query["code"][0]


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_authorize_redirect_includes_code_and_state(client: TestClient) -> None:
    location = authorize(client)
    parsed = urlparse(location)
    query = parse_qs(parsed.query)
    assert query == snapshot(
        {
            "code": [
                "eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIiwgInNjb3BlIjogInVzZXI6ZW1haWwifQ=="
            ],
            "state": ["state-123"],
        }
    )


def test_authorize_preserves_existing_query(client: TestClient) -> None:
    location = authorize(client, redirect_uri="https://example.com/callback?foo=bar")
    query = parse_qs(urlparse(location).query)
    assert query == snapshot(
        {
            "foo": ["bar"],
            "code": [
                "eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIiwgInNjb3BlIjogInVzZXI6ZW1haWwifQ=="
            ],
            "state": ["state-123"],
        }
    )


def test_authorize_fail_client_redirects_error(client: TestClient) -> None:
    location = authorize(client, client_id=FAIL_CLIENT_ID)
    query = parse_qs(urlparse(location).query)
    assert query == snapshot(
        {
            "error": ["invalid_client"],
            "error_description": ["Client id is configured to fail in this mock"],
            "state": ["state-123"],
        }
    )


def test_token_json_response(client: TestClient) -> None:
    location = authorize(client, scope="user:email")
    code = extract_code(location)
    response = exchange(client, code, accept="application/json")
    assert response.status_code == 200
    payload = response.json()
    assert payload == snapshot(
        {
            "access_token": "eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIiwgInNjb3BlIjogInVzZXI6ZW1haWwifQ==",
            "token_type": "bearer",
            "scope": "user:email",
        }
    )


def test_token_form_response(client: TestClient) -> None:
    location = authorize(client, scope="user:email")
    code = extract_code(location)
    response = exchange(client, code)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-www-form-urlencoded")
    payload = dict(parse_qsl(response.text))
    assert payload == snapshot(
        {
            "access_token": "eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIiwgInNjb3BlIjogInVzZXI6ZW1haWwifQ==",
            "token_type": "bearer",
            "scope": "user:email",
        }
    )


def test_token_error_fail_client_form(client: TestClient) -> None:
    response = exchange(client, "invalid-code", client_id=FAIL_CLIENT_ID)
    assert response.status_code == 400
    payload = dict(parse_qsl(response.text))
    assert payload == snapshot(
        {
            "error": "invalid_client",
            "error_description": "Client id is configured to fail in this mock",
        }
    )


def test_user_email_requires_scope(client: TestClient) -> None:
    location = authorize(client, scope="read:user")
    code = extract_code(location)
    token_response = exchange(client, code, accept="application/json")
    token = token_response.json()["access_token"]

    user_response = client.get("/api/user", headers=auth_header(token))
    assert user_response.status_code == 200
    assert user_response.json() == snapshot(
        {
            "id": 1431318336,
            "login": "test",
            "name": "Test",
            "email": None,
            "avatar_url": "https://avatars.githubusercontent.com/u/1431318336",
            "html_url": "https://github.com/test",
            "type": "User",
            "site_admin": False,
            "company": None,
            "blog": None,
            "location": None,
            "bio": None,
            "twitter_username": None,
            "public_repos": 0,
            "public_gists": 0,
            "followers": 0,
            "following": 0,
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
    )

    emails_response = client.get("/api/user/emails", headers=auth_header(token))
    assert emails_response.status_code == 403
    assert emails_response.json() == snapshot({"detail": "Requires user:email scope"})


def test_user_emails_with_scope(client: TestClient) -> None:
    location = authorize(client, scope="user:email")
    code = extract_code(location)
    token_response = exchange(client, code, accept="application/json")
    token = token_response.json()["access_token"]

    emails_response = client.get("/api/user/emails", headers=auth_header(token))
    assert emails_response.status_code == 200
    payload = emails_response.json()
    assert payload == snapshot(
        [
            {
                "email": "test@example.com",
                "primary": True,
                "verified": True,
                "visibility": "private",
            }
        ]
    )
