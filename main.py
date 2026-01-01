"""
GitHub OAuth Mock Server

A mock implementation of GitHub's OAuth endpoints for testing.
Email verification status is determined by the email pattern:
- Emails starting with "unverified" → verified: false
- All other emails → verified: true

Endpoints:
- GET  /login/oauth/authorize - Login form
- POST /login/oauth/authorize - Process login and redirect
- POST /login/oauth/access_token - Token exchange
- GET  /api/user - User profile
- GET  /api/user/emails - User emails with verification status
"""

import hashlib
import secrets
import time
from typing import Annotated
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel


app = FastAPI(
    title="GitHub OAuth Mock",
    description="Mock GitHub OAuth server for testing",
)


# In-memory storage for auth codes and tokens
auth_codes: dict[str, dict] = {}
access_tokens: dict[str, dict] = {}


class GitHubUser(BaseModel):
    """GitHub user profile response."""

    id: int
    login: str
    name: str | None
    email: str | None
    avatar_url: str
    html_url: str
    type: str = "User"
    site_admin: bool = False
    company: str | None = None
    blog: str | None = None
    location: str | None = None
    bio: str | None = None
    twitter_username: str | None = None
    public_repos: int = 0
    public_gists: int = 0
    followers: int = 0
    following: int = 0
    created_at: str = "2020-01-01T00:00:00Z"
    updated_at: str = "2024-01-01T00:00:00Z"


class GitHubEmail(BaseModel):
    """GitHub email response."""

    email: str
    primary: bool
    verified: bool
    visibility: str | None = "private"


def is_email_verified(email: str) -> bool:
    """Determine if email should be marked as verified based on pattern."""
    return not email.lower().startswith("unverified")


def generate_user_id(email: str) -> int:
    """Generate a consistent user ID from email."""
    return int(hashlib.md5(email.encode()).hexdigest()[:8], 16)


def generate_login(email: str) -> str:
    """Generate a login/username from email."""
    return email.split("@")[0].replace(".", "").replace("+", "")


@app.get("/")
def root():
    """Health check and info endpoint."""
    return {
        "service": "GitHub OAuth Mock",
        "description": "Email verification is determined by email pattern",
        "rules": {
            "unverified@*": "verified: false",
            "*": "verified: true",
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
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>GitHub OAuth Mock - Sign In</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background: #0d1117;
                color: #c9d1d9;
            }}
            .container {{
                background: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 32px;
                width: 340px;
            }}
            h1 {{
                color: #58a6ff;
                font-size: 24px;
                margin: 0 0 8px 0;
                text-align: center;
            }}
            .subtitle {{
                color: #8b949e;
                font-size: 14px;
                text-align: center;
                margin-bottom: 24px;
            }}
            label {{
                display: block;
                margin-bottom: 8px;
                font-size: 14px;
            }}
            input[type="email"] {{
                width: 100%;
                padding: 10px 12px;
                border: 1px solid #30363d;
                border-radius: 6px;
                background: #0d1117;
                color: #c9d1d9;
                font-size: 14px;
                box-sizing: border-box;
                margin-bottom: 16px;
            }}
            input[type="email"]:focus {{
                outline: none;
                border-color: #58a6ff;
                box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.3);
            }}
            button {{
                width: 100%;
                padding: 10px 16px;
                background: #238636;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
            }}
            button:hover {{
                background: #2ea043;
            }}
            .hint {{
                margin-top: 20px;
                padding: 12px;
                background: #0d1117;
                border-radius: 6px;
                font-size: 12px;
                color: #8b949e;
            }}
            .hint code {{
                background: #30363d;
                padding: 2px 6px;
                border-radius: 3px;
                color: #f0883e;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>GitHub Mock</h1>
            <p class="subtitle">Sign in to continue to the application</p>

            <form method="POST">
                <input type="hidden" name="client_id" value="{client_id}">
                <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                <input type="hidden" name="scope" value="{scope}">
                <input type="hidden" name="state" value="{state or ''}">
                <input type="hidden" name="code_challenge" value="{code_challenge or ''}">
                <input type="hidden" name="code_challenge_method" value="{code_challenge_method or ''}">

                <label for="email">Email address</label>
                <input
                    type="email"
                    id="email"
                    name="email"
                    placeholder="you@example.com"
                    required
                    autofocus
                >

                <button type="submit">Sign in</button>
            </form>

            <div class="hint">
                <strong>Test hint:</strong> Use <code>unverified@...</code> to test
                with an unverified email address.
            </div>
        </div>
    </body>
    </html>
    """


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
    # Generate auth code
    code = secrets.token_urlsafe(32)

    # Store auth data with the email
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state if state else None,
        "code_challenge": code_challenge if code_challenge else None,
        "code_challenge_method": code_challenge_method if code_challenge_method else None,
        "email": email,
        "created_at": time.time(),
    }

    # Build redirect URL
    params = {"code": code}
    if state:
        params["state"] = state

    redirect_url = f"{redirect_uri}?{urlencode(params)}"
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
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

    if not code:
        raise HTTPException(status_code=400, detail="Missing code")

    if code not in auth_codes:
        raise HTTPException(status_code=400, detail="Invalid code")

    auth_data = auth_codes[code]

    # Check expiration (10 minutes)
    if time.time() - auth_data["created_at"] > 600:
        del auth_codes[code]
        raise HTTPException(status_code=400, detail="Code expired")

    # TODO: Verify code_challenge if PKCE was used

    # Generate access token
    access_token = secrets.token_urlsafe(32)

    # Store token data with email
    access_tokens[access_token] = {
        "email": auth_data["email"],
        "scope": auth_data["scope"],
        "created_at": time.time(),
    }

    # Clean up used code
    del auth_codes[code]

    response_data = {
        "access_token": access_token,
        "token_type": "bearer",
        "scope": auth_data["scope"],
    }

    # Check Accept header for response format
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        return response_data

    # Default: return as form-urlencoded (GitHub's default)
    return urlencode(response_data)


async def _get_user_data(authorization: str) -> tuple[str, dict]:
    """Extract token and get user data."""
    token = authorization.replace("Bearer ", "").replace("bearer ", "")
    if token not in access_tokens:
        raise HTTPException(status_code=401, detail="Bad credentials")
    return token, access_tokens[token]


# Support both /api/user and /api/v3/user (GitHub Enterprise style)
@app.get("/api/user", response_model=GitHubUser)
@app.get("/api/v3/user", response_model=GitHubUser)
async def get_user(authorization: Annotated[str, Header()]):
    """Get authenticated user's profile."""
    _, token_data = await _get_user_data(authorization)
    email = token_data["email"]

    return GitHubUser(
        id=generate_user_id(email),
        login=generate_login(email),
        name=generate_login(email).title(),
        email=email,
        avatar_url=f"https://avatars.githubusercontent.com/u/{generate_user_id(email)}",
        html_url=f"https://github.com/{generate_login(email)}",
    )


@app.get("/api/user/emails", response_model=list[GitHubEmail])
@app.get("/api/v3/user/emails", response_model=list[GitHubEmail])
async def get_user_emails(authorization: Annotated[str, Header()]):
    """Get authenticated user's emails with verification status."""
    _, token_data = await _get_user_data(authorization)
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
async def get_user_orgs(authorization: Annotated[str, Header()]):
    """Get user's organizations (empty for mock)."""
    return []


@app.get("/api/user/repos")
@app.get("/api/v3/user/repos")
async def get_user_repos(authorization: Annotated[str, Header()]):
    """Get user's repositories (empty for mock)."""
    return []
