# xc_export — Operator Guide

*Languages: **English** (this file) · [Русский](USAGE.ru.md)*

A tool for the person who collects pilot tracks at a competition. It downloads flight
tracks (IGC) for a chosen day from **xcontest.org** and saves them, ready-named, into one
folder for your scoring program. It can also collect tracks that pilots submitted through a
Telegram bot (from a local folder or from a server over SFTP).

---

## 1. What you need

- **`xc_export.exe`** (single file) — or the Python source with a virtual environment.
- **`xc_export_conf.ini`** — settings (must be in the same folder as the exe).
- **`xc_cookie_1.txt`** — your xcontest login session (you create it, see §4).
- **Attendance list** `.xlsx` — the list of pilots for the event (optional but usual).

> Put `xc_export.exe`, `xc_export_conf.ini` and the `xc_cookie_*.txt` files **in the same
> folder**, and run the exe **from that folder**. Double-clicking from another location will
> not find the config.

Running from Python instead of the exe:
```
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe main.py
```

---

## 2. The daily workflow (short version)

1. Open `xc_export_conf.ini`, set **`date`** to the competition day (`YYYY-MM-DD`).
2. Refresh your login cookie into `xc_cookie_1.txt` (§4) — do this once; redo it only when
   the session expires.
3. Run `xc_export.exe` (or `xc_export.cmd`).
4. Tracks appear in the output folder: `track_dir\<date> <date_name>\` (§7).

---

## 3. How pilots are selected

For the configured **contest** (`src`), **day** (`date`) and optional **country**
(`country`), the tool asks xcontest for that day's flights and downloads a track when the
pilot's **xcontest username** is listed in the attendance file's **`Login`** column.

- If you provide **no** attendance list, it downloads **all** flights matching
  `src`/`date`/`country`.
- Telegram-bot tracks are matched by the **`tg_username`** column instead (§8).

---

## 4. Getting your xcontest cookie (most important step)

The tool logs in by reusing the session from your own browser (xcontest now requires a
Cloudflare "I'm human" check that only a real browser can pass). You copy the session once:

1. In **Chrome or Edge**, go to `https://www.xcontest.org` and **log in** (pass the
   Cloudflare check).
2. Press **F12** → open the **Network** tab.
3. Press **F5** to reload the page.
4. Click the first request to `www.xcontest.org` (e.g. `world/en/`) in the list.
5. Scroll to **Request Headers**, find the header named **`cookie`**.
6. Copy its **entire value** (a long line like `PHPSESSID=...; other=...`).
7. Paste it into **`xc_cookie_1.txt`** (one line) and save.

That's it — the tool reads this file at startup. When the session expires you'll see an
`HTTP 403 — session expired` message; just repeat these steps to refresh the file.

> **Two logins?** You can define several accounts (see `[ACCOUNT:*]` in §6), each with its
> own cookie file. If xcontest rate-limits one, the tool automatically switches to the next.

---

## 5. Attendance list (.xlsx)

A normal Excel sheet with one row per pilot. Column **names** matter (case-sensitive):

| Column        | Purpose                                                                   |
|---------------|---------------------------------------------------------------------------|
| `Login`       | Pilot's **xcontest username** — used to select flights to download.       |
| `tg_username` | Pilot's **Telegram username** — used to match Telegram-bot tracks (§8).   |
| `Number`, `Name`, … | Any extra columns you like — usable in the file name (see §6, `[XLSX-…]`). |

Every column becomes available in the output file name as `[XLSX-<ColumnName>]`
(e.g. `[XLSX-Name]`, `[XLSX-Number]`, `[XLSX-Login]`).

---

## 6. Configuration — `xc_export_conf.ini`

### `[MAIN]`

| Key | Req. | Meaning |
|-----|------|---------|
| `src` | yes | Contest path, e.g. `world/2026`. |
| `date` | yes | Competition day, `YYYY-MM-DD`. **Change this each day.** |
| `date_name` | no | Suffix added to the output folder name (e.g. `TrainDay`). |
| `country` | no | Country filter, e.g. `KZ`. Omit to include all. |
| `track_dir` | yes | Base output folder for saved tracks. |
| `attendence_list_file` | no | Path to the attendance `.xlsx`. |
| `igc_file_name` | yes | Output file-name template (see tokens below). |
| `tracks_loaded_file_name` | no | Progress file, default `tracks_loaded.json`. |
| `xc_max_flights` | no | Max flights to request per day, default `1000`. |
| `only_check` | no | `yes` = list matches only, download nothing. Default `no`. |
| `key` | no | xcontest API key (a working default is built in). |
| `lng` | no | Interface language, default `en`. |
| `log_level` | no | `DEBUG` / `INFO` / `ERROR`. |
| `log_file` | no | Also write the log to this file. |
| `tg_bot_dir` | no | Folder with Telegram-bot tracks (see §8). |
| `tg_bot_mode` | no | `local` (default) or `ssh` (see §8). |

**File-name template tokens** (`igc_file_name`):

- `[XLSX-<Column>]` — any attendance-list column, e.g. `[XLSX-Name]`, `[XLSX-Number]`.
- `[YYYY] [MM] [DD] [H24] [MI] [SEC]` — flight date/time (Telegram tracks use `000000` time).
- `[TYPE]` — `xcontest` or `tg`.
- `[LOGIN]`, `[XC_NAME]`, `[XC_CIVL]` — pilot login / name / CIVL id (xcontest tracks).
- `[TG_USERNAME]` — Telegram username (Telegram tracks).

Example: `[XLSX-Name].[YYYY][MM][DD]-[H24][MI][SEC].[TYPE].[XLSX-Number].igc`
→ `Alexander Fedorov.20260729-055200.xcontest.124.igc`

### `[ACCOUNT:*]` — one or more login sessions

```ini
[ACCOUNT:1]
cookie_file=xc_cookie_1.txt

[ACCOUNT:2]
cookie_file=xc_cookie_2.txt
```
Each account points to its own cookie file (§4). At least one is required. On rate-limit /
expired session the tool rotates to the next account.

### `[SSH]` — only when `tg_bot_mode=ssh`

```ini
[SSH]
host=example.com
port=22
username=user
password=secret
```

---

## 7. Running it and where tracks go

Run `xc_export.exe` (a console window opens and logs progress). Output goes to:

```
<track_dir>\<date> <date_name>\
```
e.g. `D:\Tracks\2026-07-29 TrainDay\`. Inside you get the IGC files plus a
`tracks_loaded.json` that records what's already downloaded — so re-running the same day only
fetches **new** tracks (safe to run repeatedly through the day).

---

## 8. Telegram-bot tracks (optional)

If pilots also submit via a Telegram bot, set `tg_bot_dir` to the folder that holds those
files. The tool looks in `tg_bot_dir/<date>/` and expects file names in the form:

```
<date>#<tg_username>#<original_igc_name>
```

Files are matched to pilots by the **`tg_username`** attendance-list column and copied into
the same output folder, named by your `igc_file_name` template (`[TYPE]` = `tg`).

- **`tg_bot_mode=local`** — `tg_bot_dir` is a folder on this computer.
- **`tg_bot_mode=ssh`** — `tg_bot_dir` is a path **on a server**; the tool reads it directly
  over SFTP using the `[SSH]` credentials (no drive mounting needed).

---

## 9. Troubleshooting

| Message / symptom | Meaning & fix |
|-------------------|---------------|
| `Cookie file "xc_cookie_1.txt" not found` | Create it as in §4, next to the exe. |
| `... not a valid xcontest session (expired?)` | Cookie is stale — refresh it (§4). |
| `Got HTTP 403 — session expired` | Same: re-copy the `cookie` header into the file. |
| `Got list of flights: 0` | No flights for that `src`/`date`/`country`, or wrong `date`. |
| `cannot find TG path: …` | The `tg_bot_dir/<date>` folder doesn't exist (no Telegram tracks that day) — harmless. |
| `Chrome debug…` / SSH connect errors | Check `[SSH]` host/port/username/password and the server path in `tg_bot_dir`. |
| Config error `[SSH].host MUST be defined` | `tg_bot_mode=ssh` but the `[SSH]` section is missing/incomplete. |

**Security note:** cookie files and any `[SSH]` password are secrets — don't share them or
commit them to a public repository.

---

© 2026 Alexander Fedorov · <wind3style@gmail.com>
