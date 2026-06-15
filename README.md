# Burp Dedupe

Burp Suite extension (Montoya API) that classifies each new HTTP-history entry as **UNIQUE** or **DUPE** and writes the verdict to the Notes column. Sort the Notes column → all unique rows cluster together → mass-select and feed to your scanners or other extensions.

## How it works

- Registers a `ProxyResponseHandler` (Montoya). Every response that lands in HTTP history is classified.
- A **signature** is computed from configurable parts of the request/response (method, host, path, param names, etc.).
- Signatures are SHA-256-derived 128-bit keys stored in a `ConcurrentHashMap<Signature, AtomicInteger>` — fast, thread-safe, memory-light.
- The verdict is stamped into the Notes column as `[DEDUPE] UNIQUE` or `[DEDUPE] DUPE x3`. The row is highlighted too (optional). Highlight color depends on **both** the dedupe verdict and the listener port — see the matrix below.

## Port highlighter (attacker / victim tagging)

- Registers a `ProxyRequestHandler` that injects identifying headers into traffic by the **listener port** it arrived on — handy for multi-account (IDOR/BOLA) testing where each account browses through its own proxy listener.
- Row colors are decided centrally in `PortHighlightHandler.colorFor(...)` and applied by the dedupe handler (live) and the history re-stamper, so both stay consistent. Colors are **per port and per verdict**. Defaults (edit `PORT_RULES` at the top of `PortHighlightHandler.java` and rebuild):

  | Listener port | Unique | Duplicate | Injected header |
  |---|---|---|---|
  | **8082** (attacker) | green | yellow | `X-AI-Use: attacker` |
  | **8083** (victim) | red | gray | `X-AI-Use: victim` |
  | any other port | yellow | gray | — |

- Because color is verdict-aware, it's applied after classification — so the "Highlight rows" / "Stamp Notes" toggles must be on for colors to show.

## Build

Requires JDK 21+.

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@21/21.0.9/libexec/openjdk.jdk/Contents/Home \
  ./gradlew build
```

Output: `build/libs/burp-dedupe-0.1.0.jar`

## Install in Burp

1. Burp → **Extensions** → **Installed** → **Add**
2. Extension type: **Java**
3. Select `build/libs/burp-dedupe-0.1.0.jar`
4. A new **Dedupe** tab appears at the top.

## Usage

1. Open the **Dedupe** tab.
2. Pick a preset (e.g. **Request smuggling** if you only care about path uniqueness).
3. Hit **Apply** — this also resets the seen-set so verdicts stay consistent.
4. Browse / replay traffic. New entries get stamped.
5. In **HTTP history**, click the **Notes** column header to sort. All `[DEDUPE] UNIQUE` rows cluster. Multi-select → send to your scanner / extension.

## Right-click actions (HTTP history / Site map)

Select rows, right-click → **Dedupe**:

- **Show only unique requests** — opens a separate window styled like Burp's HTTP history: columns for `# / Host / Method / URL / Status / Length / MIME / Notes`, rows tinted by their Burp **highlight color** (so attacker=green / victim=red / other=yellow carry over), the **Notes** column showing the `[DEDUPE] …` verdict + `[attacker]/[victim] port N` tag, and read-only request/response viewers beneath. Burp's API can't filter its own history table, so the deduplicated set is shown here instead. (Out-of-scope/static `SKIP` rows and known duplicates are excluded.)
  - This is a **snapshot** of the current selection (also on **Ctrl+9** with rows selected). For an auto-updating view, use the **Dedupe Live** tab or the **Live unique window** (below).
  - The table is **multi-select** (Ctrl/Cmd- or Shift-click). Toolbar actions apply to the whole selection.
  - **Send to Repeater** — sends each selected request to a new Repeater tab, **named by its method + path** (e.g. `GET /test/lasd/something/234`, `POST /sdfsd/dff`) so tabs are easy to tell apart. (Tip: point [Autorize](https://github.com/Quitten/Autorize) at Repeater and hit Send to run its authz checks.)
  - **Save request(s)** — saves all selected requests **and their responses into one `.http` file** (each in its own `####` section); pick the destination in the save dialog.
  - **Magic Cookie** — reissues the selected request(s) with a user-supplied **auth set** (cookies / bearer token / custom headers) swapped in. It strips the request's existing `Cookie` and `Authorization` (plus any header you list) and sends with **only** the credentials you provide — method, path, body and every other header unchanged. You enter the auth set once in a dialog (one `Name: value` per line) and it's remembered across windows and restarts (Montoya preferences); results open in their own window so you can compare statuses. Ideal for same-request / different-identity **IDOR/BOLA** checks (e.g. replay an attacker's request with the victim's session and watch for a `200`).
  - **Match & Replace (IDOR)** — reissues the selected request(s) with a find/replace applied to the **path/query**, the **body**, or **both** (literal, or tick **regex**). Built for IDOR/BOLA: swap an object id (e.g. `1001`→`1002`) and watch the results for a `200` where another identity's value should be denied. **Only requests that actually contain the match are reissued** — the rest are skipped, so you hit only the endpoints carrying that id, with just the id changed. Method, headers and untouched parts go out as-is (`Content-Length` is refreshed for you). The match/replace/scope settings are remembered (Montoya preferences).
  - **Clear** — empties this window (the collected rows). In the live window, new `[DEDUPE] UNIQUE` requests keep arriving after; already-cleared rows don't reappear.
  - **Filter box** — filters by any text in the **request** (path, query, headers, body), the **response body**, or the columns (Host / Method / URL / Status / MIME / Notes); plain substring by default, or tick **regex** for a case-insensitive regular expression. Full Bambda (Java-snippet) filtering isn't possible from an extension — Montoya only exposes `bambda().importBambda(...)` to *load* a Bambda into Burp, not to *evaluate* one — so this is a fast text/regex filter. For real Bambda, use Burp's native HTTP-history filter bar on these same rows.
- **Send unique to Organizer** — ships only the unique requests (dupes filtered) to Burp Organizer, optionally applying header overrides, tagged with a batch label.

> Note: if Autorize is enabled and intercepting **Proxy** traffic, your proxied unique requests are already being tested automatically — the button is for pushing a specific request on demand.

## Live unique view — the **Dedupe Live** tab (or Ctrl+9 window)

Two ways in, same real-time view — **no selection needed**:

- **Dedupe Live** — an always-on Burp suite tab (next to **Dedupe**); it's there the moment the extension loads.
- **Ctrl+9** in **HTTP history** / the **Site map** — with rows **selected** (e.g. **Ctrl+A**) it opens *those* requests, deduplicated, in a snapshot window; with **nothing selected** it opens the live view in a window. (The **Live unique window ▶** button on the **Dedupe** tab always opens the live view.)

It's an HTTP-history-style view that **automatically collects every Proxy HTTP-history entry stamped `[DEDUPE] UNIQUE`** in its Notes — and only those. New uniques appear on their own as you browse (it refreshes a couple of times a second, scanning history **incrementally** so it stays smooth even when history is large); the duplicates Burp already folded away (`[DEDUPE] DUPE …`) never show, and uniques already in history are collected the moment you open it.

The toolbar acts on the multi-selected rows: **Send to Repeater**, **In-scope only** (keep only rows whose URL is in Target scope), **Save**, **Magic Cookie**, **Match & Replace**, **Clear**, **Live export → file**, and a **filter** box (substring or regex).

**Inline repeater:** select a row to load it into the **editable** request editor beneath the table, tweak it, then **Send ▶** — or **Ctrl+Space** / **Cmd+Enter**. The response shows on the right with a status / length / timing line, so you can modify a logged request and resend without leaving the view (it uses Burp's HTTP client, so it lands in **Logger**, not Proxy history). On macOS, Ctrl+Space may be reserved for input-source switching — use **Cmd+Enter** there.

- It **re-reads the verdict the proxy handler already wrote** — it does *not* re-deduplicate. So keep **verdict stamping enabled** (that's what writes the `[DEDUPE]` note); with stamping off, nothing is collected.
- It also picks up rows that the **Stamp existing history** pass marks `UNIQUE` after the view is already open.
- Why a dedicated view: Burp's own HTTP history already shows these notes live, but the Montoya API can't *filter* that table to just the `UNIQUE` rows — so this view does. (The tab lives for the session; closing the Ctrl+9 window stops that window's polling.)

## Live export to a file (for Claude Code / AI)

Burp's MCP server can't see a custom extension window, so to hand your deduped requests to an AI we use the **filesystem** as the shared channel. With the **Live export → file** toggle on (default in the live window), the window writes — debounced — to a stable, per-project folder:

```
~/.burp-dedupe/<burp-project-name>/
  live-unique.http   ← every unique request it collects, as it arrives
  selection.http     ← just the rows you currently have selected
```

The folder is named after the **current Burp project** (`api.project().name()`), so each engagement gets its own. Each entry is the request **and** its response in a `####`-delimited block, with a header line (project / time / count). The toggle is **on by default in the live window** (off in snapshot/results windows so they don't overwrite the files — flip it on there for a one-off).

**Workflow:** open the **Dedupe Live** tab (or the Ctrl+9 window) → it fills with `[DEDUPE] UNIQUE` requests and mirrors them automatically → in **Claude Code**: *"read `~/.burp-dedupe/<project>/live-unique.http`"* for the full deduped set, or `selection.http` for just what you've highlighted. The folder path is logged to the extension's **Output** on open and shown in the **status bar** after each write.

## Presets

| Preset | What it considers unique |
|---|---|
| Default | method + host + path + sorted param names + status |
| Request smuggling | method + host + path only (params ignored) |
| IDOR / Auth | method + host + path (numeric IDs normalized) + sorted param names |
| XSS | method + host + path + sorted query+body param names |
| SQLi | method + host + path + sorted param names |
| SSRF | method + host + path + query param names |
| Open redirect | host + path + query param names (method-insensitive) |
| SSTI | method + host + path + param names |
| Path traversal | method + host + normalized path + query param names |
| Strict | full URL + all params + values + status + content-type |
| Custom | whatever you tick |

## Send unique to Organizer (right-click)

The main action: in **HTTP history**, select any number of rows (duplicates fine), right-click → **Dedupe → Send unique to Organizer**. The extension:

1. Recomputes signatures for the selection using the current signature config (stamps in the Notes column are not required — uniqueness is determined live).
2. Keeps the first occurrence of each signature, drops the rest.
3. If **Header overrides** are enabled, applies them to each request via `HttpRequest.withUpdatedHeader` / `withAddedHeader`.
4. Calls `api.organizer().sendToOrganizer(...)` for each unique, overridden request on a background thread.

From there, right-click items in **Organizer → Extensions → …** to feed them to any extension. The extension reads the request bytes you handed it — including your overridden headers — even if it dispatches via raw sockets (e.g. HTTP Request Smuggler, Turbo Intruder), because the source bytes are what those extensions sample for their attacks.

### Header overrides

In the Dedupe tab's **Header overrides** section:

- Paste raw header lines (e.g. `Cookie: a=1; b=2`, `Authorization: Bearer …`), one per line. Blank lines and `#` comments are ignored.
- Pick **Replace if present, add if missing** or **Replace only (don't add new headers)**.
- Tick **Apply header overrides when sending to Organizer** and hit **Apply**.
- Reserved headers (`Host`, `Content-Length`, `Transfer-Encoding`) are rejected with a warning logged.
- Malformed lines are reported per-line in the extension log.

## Notes / edge cases

- **Existing history can be retro-stamped.** Use the **"Stamp existing history"** button in the Dedupe tab to walk `api.proxy().history()` and apply verdicts in-place. Or tick **"Auto-stamp existing history when extension loads"** to do it automatically on every load (handy when reopening saved projects). The job runs on a background thread and can be cancelled. The seen-set is reset before the pass so counts stay consistent.
- **Changing the config resets the seen-set** so you don't get mixed verdicts under different signature rules.
- **Static assets** (`.css`, `.js`, images, fonts, etc.) are skipped by default to keep the seen-set small.
- **Memory cap**: at *Max tracked signatures* (default 200k) new keys stop being added and the verdict becomes `OVRF` — prevents OOM on huge engagements.
- **Out-of-scope**: enable "In-scope only" to skip everything not in target scope.
- **Path normalization** (numeric IDs → `{n}`, UUIDs → `{uuid}`, long hex → `{hex}`) is opt-in per preset; turn it on for IDOR / path traversal.
- Header inclusion: free-text field (comma-separated, lowercase) — useful to include `host` aliases on Host header attacks, etc.
