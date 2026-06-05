# Deduplighter

Burp Suite extension (Montoya API) that **color-codes proxy traffic by listener port** (attacker / victim tagging, with header injection) **and deduplicates** HTTP history — classifying each new entry as **UNIQUE** or **DUPE**, writing the verdict to the Notes column, with a filterable, Burp-history-style unique-requests viewer.

> **v2.0.0** — rewritten in Java/Montoya. Based on [`sw33tLie/burp-dedupe`](https://github.com/sw33tLie/burp-dedupe) (MIT); adds port-based highlighting + header injection, a port×verdict highlight matrix, and the unique-requests window. The previous Jython `port_highlighter.py` (v1) remains in this repo's git history.

Sort the Notes column → all unique rows cluster together → mass-select and feed to your scanners or other extensions.

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

Output: `build/libs/deduplighter-2.0.0.jar`

## Install in Burp

1. Burp → **Extensions** → **Installed** → **Add**
2. Extension type: **Java**
3. Select `build/libs/deduplighter-2.0.0.jar`
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
  - **Send to Repeater** — a toolbar button sends the selected request to a new Repeater tab. (Tip: point [Autorize](https://github.com/Quitten/Autorize) at Repeater and hitting Send there runs its authz checks.)
  - **Filter box** — filters the table across all columns (Host / Method / URL / Status / MIME / Notes); plain substring by default, or tick **regex** for a case-insensitive regular expression. Full Bambda (Java-snippet) filtering isn't possible from an extension — Montoya only exposes `bambda().importBambda(...)` to *load* a Bambda into Burp, not to *evaluate* one — so this is a fast text/regex filter. For real Bambda, use Burp's native HTTP-history filter bar on these same rows.
- **Send unique to Organizer** — ships only the unique requests (dupes filtered) to Burp Organizer, optionally applying header overrides, tagged with a batch label.

> Note: if Autorize is enabled and intercepting **Proxy** traffic, your proxied unique requests are already being tested automatically — the button is for pushing a specific request on demand.

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
