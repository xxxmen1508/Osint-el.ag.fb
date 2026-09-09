# Unified AI Data Intelligence Lab V3

V3 adds the first real Google Drive OAuth connection.

Important:
- Never put Google Client Secret or Refresh Token in GitHub.
- Add secrets only in Render Environment Variables.
- Current V3 only verifies/list files in the configured Drive folder.
- It does NOT yet index the large datasets; that is the next stage.
- The zero-hallucination rule is preserved.

Render environment:
ADMIN_PASSWORD
SESSION_SECRET
DRIVE_FOLDER_ID
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
GOOGLE_REFRESH_TOKEN
GOOGLE_REDIRECT_URI=https://osint-el-ag-fb.onrender.com/oauth2callback
