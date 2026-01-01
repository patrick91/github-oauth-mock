# GitHub OAuth Mock

A mock implementation of GitHub's OAuth endpoints for testing. Email verification status is determined by the email pattern you enter.

## Email Verification Rules

| Email Pattern | Verified |
|---------------|----------|
| `unverified@*` | `false` |
| Any other email | `true` |

## Quick Start

```bash
# Start the server
uv run fastapi dev

# Or with specific port
uv run fastapi dev --port 9000
```

Visit http://localhost:8000/docs for the API documentation.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login/oauth/authorize` | GET | Shows login form |
| `/login/oauth/authorize` | POST | Processes login, redirects with code |
| `/login/oauth/access_token` | POST | Token exchange |
| `/api/user` | GET | User profile |
| `/api/user/emails` | GET | User emails with verification status |

## Usage in E2E Tests

### Playwright Example

```typescript
import { test, expect } from "@playwright/test"

test("login with verified email", async ({ page }) => {
  await page.goto("/login")
  await page.getByRole("button", { name: "Log In with GitHub" }).click()

  // Mock shows login form - enter a normal email
  await page.getByLabel("Email address").fill("test@example.com")
  await page.getByRole("button", { name: "Sign in" }).click()

  // Redirected back to app with verified user
  await expect(page).toHaveURL(/dashboard/)
})

test("login with unverified email", async ({ page }) => {
  await page.goto("/login")
  await page.getByRole("button", { name: "Log In with GitHub" }).click()

  // Enter email starting with "unverified" to get unverified status
  await page.getByLabel("Email address").fill("unverified@example.com")
  await page.getByRole("button", { name: "Sign in" }).click()

  // App should handle unverified email appropriately
  await expect(page.getByText("Please verify your email")).toBeVisible()
})
```

## Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen --no-dev
COPY main.py ./
CMD ["uv", "run", "fastapi", "run", "--host", "0.0.0.0", "--port", "8000"]
```

## License

MIT
