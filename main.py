"""
GitHub OAuth Mock Server

A stateless mock implementation of GitHub's OAuth endpoints for testing.
Email verification status is determined by the email pattern:
- Emails starting with "unverified" → verified: false
- All other emails → verified: true

This mock is completely stateless - tokens are self-contained and encode
the user's email, eliminating the need for shared storage across replicas.

Endpoints:
- GET  /login/oauth/authorize - Login form
- POST /login/oauth/authorize - Process login and redirect
- POST /login/oauth/access_token - Token exchange
- GET  /api/user - User profile
- GET  /api/user/emails - User emails with verification status
"""

import base64
import hashlib
import json
from typing import Annotated
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel


app = FastAPI(
    title="GitHub OAuth Mock",
    description="Stateless mock GitHub OAuth server for testing",
)


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


# =============================================================================
# Stateless Token Encoding/Decoding
# =============================================================================


def encode_token(email: str) -> str:
    """
    Encode email into a self-contained token.

    The token is simply base64-encoded JSON containing the email.
    This makes the mock completely stateless - no storage needed.
    """
    data = {"email": email}
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def decode_token(token: str) -> str | None:
    """
    Decode token to extract email.

    Returns None if the token is invalid or cannot be decoded.
    """
    try:
        # Handle potential padding issues
        padded = token + "=" * (4 - len(token) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        return data.get("email")
    except Exception:
        return None


# =============================================================================
# Helper Functions
# =============================================================================


def is_email_verified(email: str) -> bool:
    """Determine if email should be marked as verified based on pattern."""
    return not email.lower().startswith("unverified")


def generate_user_id(email: str) -> int:
    """Generate a consistent user ID from email."""
    return int(hashlib.md5(email.encode()).hexdigest()[:8], 16)


def generate_login(email: str) -> str:
    """Generate a login/username from email."""
    return email.split("@")[0].replace(".", "").replace("+", "")


def extract_email_from_auth(authorization: str) -> str:
    """
    Extract email from Authorization header.

    Raises HTTPException with 401 if token is invalid.
    """
    # Remove Bearer prefix (case-insensitive)
    token = authorization
    for prefix in ["Bearer ", "bearer ", "BEARER "]:
        if token.startswith(prefix):
            token = token[len(prefix) :]
            break

    email = decode_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Bad credentials")

    return email


# =============================================================================
# Endpoints
# =============================================================================


@app.get("/")
def root():
    """Health check and info endpoint."""
    return {
        "service": "GitHub OAuth Mock",
        "version": "2.0.0",
        "description": "Stateless mock - tokens are self-contained",
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
            * {{
                box-sizing: border-box;
            }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background: #ffffff;
                color: #1a1a1a;
            }}
            .container {{
                background: #ffffff;
                border: 1px solid #e5e5e5;
                border-radius: 8px;
                padding: 48px;
                width: 420px;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
            }}
            .badge {{
                display: inline-block;
                font-size: 11px;
                font-weight: 500;
                letter-spacing: 0.5px;
                text-transform: uppercase;
                color: #666666;
                margin-bottom: 12px;
            }}
            h1 {{
                color: #1a1a1a;
                font-size: 42px;
                font-weight: 700;
                margin: 0 0 12px 0;
                letter-spacing: -1px;
                line-height: 1.1;
            }}
            .subtitle {{
                color: #666666;
                font-size: 15px;
                line-height: 1.5;
                margin-bottom: 32px;
            }}
            label {{
                display: block;
                margin-bottom: 8px;
                font-size: 14px;
                font-weight: 500;
                color: #1a1a1a;
            }}
            input[type="email"] {{
                width: 100%;
                padding: 12px 14px;
                border: 1px solid #e5e5e5;
                border-radius: 6px;
                background: #ffffff;
                color: #1a1a1a;
                font-size: 15px;
                margin-bottom: 20px;
                transition: border-color 0.15s ease, box-shadow 0.15s ease;
            }}
            input[type="email"]::placeholder {{
                color: #999999;
            }}
            input[type="email"]:focus {{
                outline: none;
                border-color: #1a1a1a;
                box-shadow: 0 0 0 3px rgba(26, 26, 26, 0.08);
            }}
            button {{
                width: 100%;
                padding: 12px 20px;
                background: #1a1a1a;
                color: #ffffff;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.15s ease;
            }}
            button:hover {{
                background: #333333;
            }}
            .hint {{
                margin-top: 24px;
                padding: 16px;
                background: #f8f8f8;
                border: 1px solid #e5e5e5;
                border-radius: 6px;
                font-size: 13px;
                color: #666666;
                line-height: 1.5;
            }}
            .hint strong {{
                color: #5f6f52;
                font-weight: 600;
            }}
            .hint code {{
                background: #1a1a1a;
                padding: 3px 8px;
                border-radius: 4px;
                font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
                font-size: 12px;
                color: #c586c0;
            }}
            .divider {{
                display: flex;
                align-items: center;
                margin: 24px 0;
                color: #999999;
                font-size: 12px;
            }}
            .divider::before,
            .divider::after {{
                content: "";
                flex: 1;
                height: 1px;
                background: #e5e5e5;
            }}
            .divider::before {{
                margin-right: 12px;
            }}
            .divider::after {{
                margin-left: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <span class="badge">OAuth Mock</span>
            <h1>GitHub<br>Sign In</h1>
            <p class="subtitle">Sign in to continue to the application. Use any email address for testing.</p>

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
                <strong>Testing tip:</strong> Use <code>unverified@...</code> to simulate
                an unverified email address.
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
    # Generate self-contained auth code (encodes the email)
    code = encode_token(email)

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

    # Decode email from the self-contained auth code
    email = decode_token(code)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid code")

    # Generate self-contained access token (same format, encodes email)
    access_token = encode_token(email)

    response_data = {
        "access_token": access_token,
        "token_type": "bearer",
        "scope": "user:email",
    }

    # Check Accept header for response format
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        return response_data

    # Default: return as form-urlencoded (GitHub's default)
    return urlencode(response_data)


# Support both /api/user and /api/v3/user (GitHub Enterprise style)
@app.get("/api/user", response_model=GitHubUser)
@app.get("/api/v3/user", response_model=GitHubUser)
async def get_user(authorization: Annotated[str, Header()]):
    """Get authenticated user's profile."""
    email = extract_email_from_auth(authorization)

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
    email = extract_email_from_auth(authorization)

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
    _ = extract_email_from_auth(authorization)  # Validate token
    return []


@app.get("/api/user/repos")
@app.get("/api/v3/user/repos")
async def get_user_repos(authorization: Annotated[str, Header()]):
    """Get user's repositories (empty for mock)."""
    _ = extract_email_from_auth(authorization)  # Validate token
    return []
