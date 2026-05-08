# PunchCard — Simple Time Tracking

A lightweight, single-page time tracking app for small teams. Built with plain HTML/CSS/JS and [Supabase](https://supabase.com) for the backend. Hosted on GitHub Pages — no build step required.

**Live site:** https://lsudigitalart.github.io/time-clock/

---

## Features

### For Employees
- **Clock in / out** with optional notes
- **Automatic shift end** — defaults to 8 hours, configurable per shift
- **Time off requests** — submit a date range (vacation, sick leave, personal, etc.)
- **My History** — view all past shifts with duration and notes
- **Account settings** — change display name, email, and password

### For Admins
- **Workplace dashboard** — see all employees and their hours for the current week
- **Invite system** — generate a shareable invite link/code; employees enter the code at signup
- **Time off approvals** — approve or deny requests spanning any date range
- **Google Sheets sync** — push all time entries and time off requests to a connected spreadsheet with one button

---

## Tech Stack

| Layer | Tech |
|---|---|
| Frontend | HTML, CSS, vanilla JS (no framework, no build) |
| Auth & Database | [Supabase](https://supabase.com) (Postgres + RLS + Auth) |
| Hosting | GitHub Pages (served from `main` branch root) |
| Email | Supabase SMTP with custom branded templates |
| Sheets export | Google Apps Script web app |

---

## Database Schema

Tables (all with Row Level Security):

- **`profiles`** — one row per user (`id`, `full_name`, `role`)
- **`workplaces`** — workspace record (`name`, `admin_id`, `hours_per_week`)
- **`workplace_members`** — join table linking users to a workplace with a role
- **`time_entries`** — individual shifts (`clock_in`, `clock_out`, `notes`, `workplace_id`)
- **`time_off_requests`** — date-range requests (`start_date`, `end_date`, `reason`, `status`)

See [`setup.sql`](setup.sql) for the full schema, RLS policies, and the new-user trigger.

---

## Local Setup

1. Clone the repo
2. Create a Supabase project and run [`setup.sql`](setup.sql) in the SQL editor
3. Fill in your project credentials at the top of `index.html`:
   ```js
   const SB_URL = 'https://your-project.supabase.co';
   const SB_KEY = 'your-anon-key';
   ```
4. Open `index.html` in a browser — no server needed

---

## Deploying to GitHub Pages

```bash
git add .
git commit -m "initial deploy"
git push origin main
```

Then enable Pages in your repo settings (source: `main` branch, root folder). Update `site_url` in `supabase/config.toml` and run:

```bash
supabase link --project-ref <your-project-ref>
supabase config push
```

---

## Google Sheets Sync (Admin)

1. Create a new Google Sheet
2. Click **Extensions → Apps Script**
3. Paste the script shown in the Admin panel's **"How to set up"** section
4. Deploy as a **Web App** (Execute as: Me, Access: Anyone)
5. Paste the web-app URL into the Admin panel and click **Save**
6. Click **Sync Time Entries + Time Off** to push all data

Each sync clears and rewrites the relevant sheet tab with the latest data.

---

## Email Templates

Custom branded emails live in `supabase/templates/`:

- `confirm.html` — sent on signup to confirm the user's email
- `reset.html` — sent when a user requests a password reset

Templates are deployed via `supabase config push` using settings in `supabase/config.toml`.
