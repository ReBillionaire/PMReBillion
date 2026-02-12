# ReBillion PM — Deployment Guide

## Overview

This guide walks through deploying the ReBillion PM tool to Vercel with Vercel Postgres, creating a GitHub repository, and setting up Google OAuth.

**Architecture:** Express.js app running as a Vercel serverless function, backed by Vercel Postgres.

---

## Step 1: Create GitHub Repository

1. Go to [github.com/new](https://github.com/new)
2. Fill in:
   - **Repository name:** `ReBillion_PM`
   - **Description:** `ReBillion.ai Client Onboarding Project Manager`
   - **Visibility:** Private
   - Do NOT initialize with README (we already have code)
3. Click **Create repository**
4. Copy the repository URL (e.g., `https://github.com/YOUR_USERNAME/ReBillion_PM.git`)
5. On your local machine, open terminal and run:

```bash
cd /path/to/ReBillion_PM_Vercel
git remote add origin https://github.com/YOUR_USERNAME/ReBillion_PM.git
git push -u origin main
```

If you don't have git set up locally, you can:
- Download the project folder
- Use GitHub Desktop to create the repo and push

---

## Step 2: Deploy to Vercel

### 2a. Import Project

1. Go to [vercel.com/new](https://vercel.com/new)
2. Sign in with GitHub
3. Click **Import** next to your `ReBillion_PM` repository
4. Configure project:
   - **Framework Preset:** Other
   - **Root Directory:** `./` (default)
   - **Build Command:** `echo 'Build complete'`
   - **Output Directory:** Leave empty
5. Click **Deploy** (it will fail initially — that's expected, we need the database first)

### 2b. Add Vercel Postgres Database

1. Go to your Vercel project dashboard
2. Click **Storage** tab (or go to vercel.com/dashboard → Storage)
3. Click **Create Database** → **Postgres**
4. Choose a name (e.g., `rebillion-pm-db`)
5. Select the region closest to your users
6. Click **Create**
7. Vercel automatically adds the `POSTGRES_URL` environment variable to your project

### 2c. Add Environment Variables

1. In your Vercel project, go to **Settings** → **Environment Variables**
2. Add these variables:

| Name | Value | Notes |
|------|-------|-------|
| `SESSION_SECRET` | *(generate a random 32+ char string)* | Use a password generator |
| `NODE_ENV` | `production` | |
| `GOOGLE_CLIENT_ID` | *(from Step 3)* | Skip for now if not ready |
| `GOOGLE_CLIENT_SECRET` | *(from Step 3)* | Skip for now if not ready |
| `GOOGLE_CALLBACK_URL` | `https://YOUR-VERCEL-URL.vercel.app/auth/google/callback` | Replace with your actual Vercel URL |

**To generate a session secret**, run in any terminal:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 2d. Redeploy

1. Go to your Vercel project → **Deployments** tab
2. Click the **...** menu on the latest deployment
3. Click **Redeploy**
4. The app should now be live!

### 2e. Verify Deployment

1. Visit your Vercel URL (e.g., `https://rebillion-pm.vercel.app`)
2. You should see the login page
3. Log in with default credentials: `atul` / `atul`
4. Verify Dashboard, Pipeline, and Team views work

---

## Step 3: Set Up Google OAuth

### 3a. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Click the project dropdown at the top → **New Project**
3. Name: `ReBillion PM` → Click **Create**
4. Select the new project

### 3b. Enable Google OAuth API

1. In the left sidebar: **APIs & Services** → **Library**
2. Search for **Google Identity** or **Google+ API**
3. Click **Google Identity Services** (or **Google+ API**) → **Enable**

### 3c. Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Choose **External** (for all Google accounts) → **Create**
3. Fill in:
   - **App name:** `ReBillion PM`
   - **User support email:** your email
   - **Developer contact email:** your email
4. Click **Save and Continue**
5. **Scopes:** Click **Add or Remove Scopes** → select `email` and `profile` → **Update** → **Save and Continue**
6. **Test users:** Add your Google email addresses → **Save and Continue**
7. **Summary:** Review and click **Back to Dashboard**

### 3d. Create OAuth Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **+ Create Credentials** → **OAuth client ID**
3. Application type: **Web application**
4. Name: `ReBillion PM Web`
5. **Authorized JavaScript origins:** Add your Vercel URL:
   - `https://YOUR-APP.vercel.app`
6. **Authorized redirect URIs:** Add:
   - `https://YOUR-APP.vercel.app/auth/google/callback`
   - `http://localhost:3000/auth/google/callback` (for local dev)
7. Click **Create**
8. Copy the **Client ID** and **Client Secret**

### 3e. Add Credentials to Vercel

1. Go to your Vercel project → **Settings** → **Environment Variables**
2. Add/update:
   - `GOOGLE_CLIENT_ID` = your Client ID
   - `GOOGLE_CLIENT_SECRET` = your Client Secret
   - `GOOGLE_CALLBACK_URL` = `https://YOUR-APP.vercel.app/auth/google/callback`
3. **Redeploy** the project for changes to take effect

### 3f. Verify Google Sign-In

1. Visit your app's login page
2. Click **Sign in with Google**
3. Complete the Google sign-in flow
4. You should be redirected to the app dashboard

**Note:** While the app is in "Testing" mode in Google Cloud, only test users you've added can sign in. To allow anyone, publish the app (go to OAuth consent screen → **Publish App**).

---

## Step 4: Custom Domain (Optional)

### On Vercel:

1. Go to your project → **Settings** → **Domains**
2. Add your domain (e.g., `pm.rebillion.ai`)
3. Follow Vercel's DNS instructions:
   - Add a CNAME record pointing to `cname.vercel-dns.com`
   - Or add an A record pointing to `76.76.21.21`
4. Vercel automatically provisions an SSL certificate

### Update Google OAuth:

After adding a custom domain, update your Google OAuth credentials:
1. Go to Google Cloud Console → **Credentials**
2. Edit your OAuth client
3. Add new authorized origins: `https://pm.rebillion.ai`
4. Add new redirect URI: `https://pm.rebillion.ai/auth/google/callback`
5. Update `GOOGLE_CALLBACK_URL` in Vercel env vars
6. Redeploy

---

## Default Login Credentials

| Username | Password |
|----------|----------|
| Lisa | lisa |
| Vikas | vikas |
| Julie | julie |
| Eddy | eddy |
| Atul | atul |

---

## Troubleshooting

**App shows 500 error after deploy:**
- Check Vercel Function Logs (project → Deployments → latest → Functions tab)
- Most likely: `POSTGRES_URL` not set. Ensure the Postgres database is linked.

**Google sign-in redirects to error:**
- Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set in env vars
- Verify the callback URL matches exactly in both Vercel env and Google Console
- Check that your email is added as a test user if the app isn't published

**Session expires immediately:**
- Ensure `SESSION_SECRET` is set
- Ensure cookies are set to `secure: true` (done automatically in production)

**Database tables not created:**
- The app auto-creates tables on first request. Visit any page to trigger initialization.
