# V4 – Google Drive automatic reconnect

This version keeps the existing OAuth client and PKCE flow, but after successful Google authorization it stores the returned refresh token automatically in an encrypted, Secure, HttpOnly cookie. The token is never rendered into the page or written to logs.

The `GOOGLE_REFRESH_TOKEN` environment variable remains as a fallback for existing deployments. A successful new authorization takes precedence over the old environment token.

## Deploy
1. Replace the repository files with this ZIP and commit.
2. Render: Deploy latest commit.
3. Admin → Connect Google Drive.
4. Approve Google access.
5. Return to the site; no token copy/paste is required.
6. Click the folder file check.

## Important
Keep `SESSION_SECRET` stable. The encrypted cookie is derived from it; changing it invalidates the stored browser-side connection and requires reconnecting Google Drive.
