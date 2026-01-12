"""
GitHub OAuth Mock Server

A stateless mock implementation of GitHub's OAuth endpoints for testing.
Email verification status is determined by the email pattern:
- Emails starting with "unverified" -> verified: false
- All other emails -> verified: true

This mock is completely stateless - tokens are self-contained and encode
the user's email and scope, eliminating the need for shared storage across replicas.

Endpoints:
- GET  /login/oauth/authorize - Login form
- POST /login/oauth/authorize - Process login and redirect
- POST /login/oauth/access_token - Token exchange
- GET  /api/user - User profile
- GET  /api/user/emails - User emails with verification status
"""

from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Form, Header, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .auth import (
    DEFAULT_SCOPE,
    FAIL_CLIENT_ID,
    build_redirect_url,
    decode_token,
    encode_token,
    extract_email_from_auth,
    extract_token_data_from_auth,
    generate_login,
    generate_user_id,
    is_email_verified,
    parse_scopes,
    require_scope,
    token_response,
)
from .models import GitHubEmail, GitHubUser

ROOT_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = ROOT_DIR / "templates"

app = FastAPI(
    title="GitHub OAuth Mock",
    description="Stateless mock GitHub OAuth server for testing",
)

def render_template(name: str, context: dict[str, str]) -> str:
    template = (TEMPLATES_DIR / name).read_text()
    for key, value in context.items():
        template = template.replace(f"{{{{{key}}}}}", value)
    return template


@app.get("/", response_class=HTMLResponse)
def root():
    """Serve the intro page."""
    template_path = TEMPLATES_DIR / "index.html"
    return template_path.read_text()


@app.get("/api")
def api_info():
    """Health check and info endpoint."""
    return {
        "service": "GitHub OAuth Mock",
        "version": "2.0.0",
        "description": "Stateless mock - tokens are self-contained",
        "rules": {
            "unverified@*": "verified: false",
            "*": "verified: true",
        },
        "oauth": {
            "default_scope": DEFAULT_SCOPE,
            "email_scope": "user:email",
        },
        "special_clients": {
            "fail": FAIL_CLIENT_ID,
        },
        "endpoints": {
            "authorize": "/login/oauth/authorize",
            "token": "/login/oauth/access_token",
            "user": "/api/user",
            "emails": "/api/user/emails",
        },
    }


@app.get("/login/oauth/authorize", response_class=HTMLResponse)
async def authorize_form(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(""),
    state: str | None = Query(None),
    code_challenge: str | None = Query(None),
    code_challenge_method: str | None = Query(None),
):
    """Show login form for GitHub OAuth mock."""
    return render_template(
        "authorize.html",
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state or "",
            "code_challenge": code_challenge or "",
            "code_challenge_method": code_challenge_method or "",
        },
    )


@app.post("/login/oauth/authorize")
async def authorize_submit(
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    email: Annotated[str, Form()],
    scope: Annotated[str, Form()] = "",
    state: Annotated[str, Form()] = "",
    code_challenge: Annotated[str, Form()] = "",
    code_challenge_method: Annotated[str, Form()] = "",
):
    """Process login form and redirect with auth code."""
    if client_id == FAIL_CLIENT_ID:
        params = {
            "error": "invalid_client",
            "error_description": "Client id is configured to fail in this mock",
        }
        if state:
            params["state"] = state
        redirect_url = build_redirect_url(redirect_uri, params)
        return RedirectResponse(url=redirect_url, status_code=302)

    # Generate self-contained auth code (encodes the email)
    requested_scope = scope or DEFAULT_SCOPE
    code = encode_token(email, requested_scope)

    # Build redirect URL
    params = {"code": code}
    if state:
        params["state"] = state

    redirect_url = build_redirect_url(redirect_uri, params)
    return RedirectResponse(url=redirect_url, status_code=302)


@app.post("/login/oauth/access_token")
async def token(
    request: Request,
    client_id: Annotated[str, Form()],
    client_secret: Annotated[str | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    grant_type: Annotated[str, Form()] = "authorization_code",
):
    """
    Token exchange endpoint.

    GitHub returns tokens as form-urlencoded by default,
    but accepts Accept: application/json header for JSON response.
    """
    accept = request.headers.get("accept", "")
    if client_id == FAIL_CLIENT_ID:
        return token_response(
            {
                "error": "invalid_client",
                "error_description": "Client id is configured to fail in this mock",
            },
            accept,
            status_code=400,
        )

    if grant_type != "authorization_code":
        return token_response(
            {
                "error": "unsupported_grant_type",
                "error_description": "The grant_type is invalid or unsupported.",
            },
            accept,
            status_code=400,
        )

    if not code:
        return token_response(
            {
                "error": "bad_verification_code",
                "error_description": "The code passed is incorrect or expired.",
            },
            accept,
            status_code=400,
        )

    # Decode email from the self-contained auth code
    token_data = decode_token(code)
    if not token_data or "email" not in token_data:
        return token_response(
            {
                "error": "bad_verification_code",
                "error_description": "The code passed is incorrect or expired.",
            },
            accept,
            status_code=400,
        )
    email = token_data["email"]
    scope = token_data.get("scope") or DEFAULT_SCOPE
    if not isinstance(scope, str):
        scope = DEFAULT_SCOPE

    # Generate self-contained access token (same format, encodes email)
    access_token = encode_token(email, scope)

    response_data = {
        "access_token": access_token,
        "token_type": "bearer",
        "scope": scope,
    }

    return token_response(response_data, accept)


# Support both /api/user and /api/v3/user (GitHub Enterprise style)
@app.get("/api/user", response_model=GitHubUser)
@app.get("/api/v3/user", response_model=GitHubUser)
async def get_user(authorization: Annotated[str | None, Header()] = None):
    """Get authenticated user's profile."""
    token_data = extract_token_data_from_auth(authorization)
    email = token_data["email"]
    scopes = parse_scopes(token_data.get("scope"))
    profile_email = email if "user:email" in scopes else None

    return GitHubUser(
        id=generate_user_id(email),
        login=generate_login(email),
        name=generate_login(email).title(),
        email=profile_email,
        avatar_url=f"https://avatars.githubusercontent.com/u/{generate_user_id(email)}",
        html_url=f"https://github.com/{generate_login(email)}",
    )


@app.get("/api/user/emails", response_model=list[GitHubEmail])
@app.get("/api/v3/user/emails", response_model=list[GitHubEmail])
async def get_user_emails(authorization: Annotated[str | None, Header()] = None):
    """Get authenticated user's emails with verification status."""
    token_data = extract_token_data_from_auth(authorization)
    require_scope(token_data, "user:email")
    email = token_data["email"]

    return [
        GitHubEmail(
            email=email,
            primary=True,
            verified=is_email_verified(email),
        )
    ]


# Additional endpoints that GitHub has (minimal implementations)


@app.get("/api/user/orgs")
@app.get("/api/v3/user/orgs")
async def get_user_orgs(authorization: Annotated[str | None, Header()] = None):
    """Get user's organizations (empty for mock)."""
    _ = extract_email_from_auth(authorization)  # Validate token
    return []


@app.get("/api/user/repos")
@app.get("/api/v3/user/repos")
async def get_user_repos(authorization: Annotated[str | None, Header()] = None):
    """Get user's repositories (empty for mock)."""
    _ = extract_email_from_auth(authorization)  # Validate token
    return []
