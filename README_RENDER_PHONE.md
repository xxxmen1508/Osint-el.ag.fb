
# Unified AI Data Intelligence Lab — deployment from Android

## Important
This package is a deployable prototype. I cannot publish it under your Render account from inside ChatGPT, so there is no honest way for me to give you a real `onrender.com` URL before the service is deployed in your account.

## 1. Put the project on GitHub
Create a new GitHub repository and upload the contents of this ZIP.

## 2. Deploy on Render
Create a new Web Service from that GitHub repository.
Render will detect the Dockerfile.
Set:
- Plan: Free
- ADMIN_PASSWORD: choose your private admin password
- SESSION_SECRET: generate a long random value if Render did not generate it automatically.

## 3. After deploy
Your URL will look like:
https://unified-ai-data-lab-XXXX.onrender.com

Open it in Chrome on Android.

## 4. Keep-awake monitoring
UptimeRobot's current Free plan checks every 5 minutes. A 1-minute interval is currently a paid feature. So a free monitor can reduce idle sleeping but cannot honestly be described as a 1-minute forever keep-alive.

## 5. Important limitation of this prototype
Render Free has ephemeral local storage. Therefore this prototype is for deployment/testing, not for permanent storage of your 300MB/693MB/1.7GB datasets.

The production version should put raw files in persistent external storage and metadata/indexes in a persistent database. The UI and API are intentionally structured so that storage can be replaced without changing the user-facing system.

## Zero-hallucination rule
The app returns "לא נמצא" when no stored match exists. AI must never be treated as a source of facts.
