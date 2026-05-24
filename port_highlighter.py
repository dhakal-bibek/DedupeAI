# -*- coding: utf-8 -*-
"""
Port Highlighter + AI Access Control Tester - Burp Suite Extension
=================================================================
1. Highlights ALL Proxy History requests by listener port (red/green).
2. Collects IDs seen per port from URL paths / params / JSON bodies.
3. When an ID-based request arrives, cross-tests by swapping the ID
   with an ID collected from a different port (keeping original session).
4. Uses AI to confirm privilege escalation / IDOR findings.
5. GUI Logger tab shows everything in real time.

Config: edit ROLE_MAPPINGS + AI_API_KEY below.
"""
from burp import IBurpExtender, IProxyListener, ITab
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
from javax.swing import (
    JPanel, JTextArea, JScrollPane, JButton,
    BorderFactory, SwingUtilities,
)
from java.awt import BorderLayout, Font, Color as AWTColor, FlowLayout
from java.awt.event import ActionListener
import json
import re
import time
import threading

# ===========================================================================
# CONFIGURATION
# ===========================================================================

ROLE_MAPPINGS = {
    8082: {"color": "red",    "role": "admin"},
    8083: {"color": "green",  "role": "user"},
}

AI_API_KEY = ""
AI_BASE_URL = "https://api.openai.com/v1/chat/completions"
AI_MODEL = "gpt-4o-mini"
BATCH_SIZE = 5
MIN_CONTENT_DIFF_PCT = 5
AUTO_TEST = True
ID_COLLECTION_CAP = 200           # max unique IDs stored per port

# ===========================================================================
# ID EXTRACTION
# ===========================================================================

ID_PATH_PATTERN = re.compile(r'/(\d{1,15})([/?#]|$)')
ID_UUID_PATTERN  = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I)
ID_QUERY_PATTERN = re.compile(r'[?&](id|user_id|account_id|order_id|item_id|uid|uuid|ref)=([^&\s]+)', re.I)
ID_JSON_PATTERN  = re.compile(r'"(id|user_id|account_id|uuid)"\s*:\s*"?([^",}\s]+)"?', re.I)


def _extract_ids(url_path, query, body):
    """Return set of (id_name, id_value) tuples found in the request."""
    ids = set()

    # Numeric IDs in path: /users/123
    for m in ID_PATH_PATTERN.finditer(url_path):
        ids.add(("path_id", m.group(1)))

    # UUIDs in path
    for m in ID_UUID_PATTERN.finditer(url_path):
        ids.add(("path_uuid", m.group(1)))

    # Query params like ?id=456, ?user_id=789
    if query:
        for m in ID_QUERY_PATTERN.finditer(query):
            ids.add((m.group(1), m.group(2)))

    # JSON body keys like "id": 123, "user_id": "abc"
    if body:
        try:
            b = body.strip()
            if b and b[0] in ('{', '['):
                for m in ID_JSON_PATTERN.finditer(b):
                    ids.add((m.group(1), m.group(2)))
        except Exception:
            pass

    return ids


def _replace_ids(url_path, query, body, old_id_value, new_id_value):
    """Replace all occurrences of old_id_value with new_id_value
    in path, query, and body. Returns (new_path, new_query, new_body)."""
    new_path = url_path
    new_query = query
    new_body = body

    if old_id_value:
        # Path
        new_path = url_path.replace("/" + old_id_value, "/" + new_id_value)
        # Query
        if query:
            new_query = query.replace(old_id_value, new_id_value)
        # Body
        if body:
            new_body = body.replace(old_id_value, new_id_value)

    return new_path, new_query, new_body


def _rebuild_request(helpers, http_service, original_bytes, new_path, new_query, new_body):
    """Build a new HTTP request with modified path/query/body."""
    try:
        info = helpers.analyzeRequest(http_service, original_bytes)
        headers = list(info.getHeaders())
        method = info.getMethod()

        # Rebuild request line
        protocol = "https" if http_service.getProtocol() == "https" else "http"
        host = http_service.getHost()
        port = http_service.getPort()

        path_with_query = new_path
        if new_query:
            path_with_query += "?" + new_query

        # Find and replace the first line (request line)
        first_line = "%s %s %s" % (method, path_with_query, "HTTP/1.1")
        if headers:
            headers[0] = first_line

        return helpers.buildHttpMessage(headers, new_body if new_body else "")
    except Exception:
        return None


# ===========================================================================
# SESSION EXTRACTION
# ===========================================================================

def _extract_cookies(request_bytes, helpers):
    """Get cookie + auth from a request (for session-based testing)."""
    try:
        info = helpers.analyzeRequest(request_bytes)
        headers = info.getHeaders()
        cookies = {}
        auth = None
        for h in headers:
            h = str(h)
            if h.lower().startswith("cookie:"):
                raw = h.split(":", 1)[1].strip()
                for pair in raw.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        cookies[k.strip()] = v.strip()
            elif h.lower().startswith("authorization:"):
                auth = h.split(":", 1)[1].strip()
        return {"cookies": cookies, "auth": auth}
    except Exception:
        return None


# ===========================================================================
# AI CLIENT
# ===========================================================================

class AIClient(object):

    def __init__(self, api_key, base_url, model, ext):
        self.api_key = api_key
        if not self.api_key:
            self.api_key = ext._callbacks.loadExtensionSetting(
                "port_highlighter.ai_key"
            ) or ""
            import os
            if not self.api_key:
                self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url
        self.model = model
        self.ext = ext

    def analyze(self, findings):
        if not self.api_key:
            return None
        try:
            return self._call_api(self._build_prompt(findings))
        except Exception as e:
            self.ext.log("[AI] Request failed: %s" % e)
            return None

    def _build_prompt(self, findings):
        lines = [
            "You are a pentesting assistant. Below are cross-user IDOR tests.",
            "An ID from one user's traffic was swapped into another user's request (keeping their session).",
            "For each, determine if there is a REAL access-control vulnerability.",
            "Only flag cases where a user accessed data they SHOULD NOT have access to.",
            "",
        ]
        for i, f in enumerate(findings):
            lines.append("--- Finding %d ---" % (i + 1))
            lines.append("URL (after ID swap): %s" % f.get("url", "?"))
            lines.append("Method: %s" % f.get("method", "?"))
            lines.append("Swapped ID: %s -> %s" %
                         (f.get("original_id", "?"), f.get("swapped_id", "?")))
            lines.append("Original response status: %d" %
                         f.get("original_status", 0))
            lines.append("Swapped response status: %d" %
                         f.get("swapped_status", 0))
            lines.append("Original body (trunc): %s" %
                         (f.get("original_body", "")[:1200]))
            lines.append("Swapped body (trunc): %s" %
                         (f.get("swapped_body", "")[:1200]))
            lines.append("")
        lines.append(
            'Respond in JSON: {"findings": [{"vulnerable": bool, "severity": "high/medium/low/info", "title": "...", "description": "..."}]}'
        )
        return "\n".join(lines)

    def _call_api(self, prompt):
        url = URL(self.base_url)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Authorization", "Bearer " + self.api_key)
        conn.setDoOutput(True)
        conn.setConnectTimeout(30000)
        conn.setReadTimeout(60000)

        body = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a security expert."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        })
        writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
        writer.write(body)
        writer.close()

        reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
        lines = []
        while True:
            line = reader.readLine()
            if line is None:
                break
            lines.append(line)
        reader.close()
        conn.disconnect()
        return json.loads("".join(lines))


# ===========================================================================
# GUI LOGGER
# ===========================================================================

class LoggerTab(JPanel, ITab):

    def __init__(self):
        JPanel.__init__(self)
        self.setLayout(BorderLayout(5, 5))
        self.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        self._area = JTextArea()
        self._area.setEditable(False)
        self._area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._area.setBackground(AWTColor(0x1E, 0x1E, 0x1E))
        self._area.setForeground(AWTColor(0xCC, 0xCC, 0xCC))

        scroll = JScrollPane(self._area)
        scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self.add(scroll, BorderLayout.CENTER)

        btn = JButton("Clear")
        btn.addActionListener(_ClearListener(self))
        self.add(btn, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "Port Highlighter + ACL Tester"

    def getUiComponent(self):
        return self

    def append(self, text):
        def _write():
            self._area.append(text)
            self._area.setCaretPosition(self._area.getDocument().getLength())
        SwingUtilities.invokeLater(_write)

    def clear(self):
        def _do():
            self._area.setText("")
        SwingUtilities.invokeLater(_do)


class _ClearListener(ActionListener):
    def __init__(self, tab):
        self.tab = tab
    def actionPerformed(self, event):
        self.tab.clear()


# ===========================================================================
# PARSING UTIL
# ===========================================================================

def _parse_port(listener_str):
    if not listener_str:
        return None
    m = re.search(r':(\d+)$', listener_str)
    if m:
        return int(m.group(1))
    m = re.search(r'^(\d+)$', listener_str.strip())
    if m:
        return int(m.group(1))
    return None


# ===========================================================================
# MAIN EXTENSION
# ===========================================================================

class BurpExtender(IBurpExtender, IProxyListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Port Highlighter + ACL Tester")

        self.port_config = dict(ROLE_MAPPINGS)
        self._load_config()

        # Collected IDs per port: {port: {id_value: True}}
        self._collected_ids = {}

        # Session cookies per port: {port: cookie_dict}
        self._sessions = {}

        self._findings = []
        self._tested = set()
        self._request_count = 0
        self._id_count = 0
        self._test_count = 0
        self._vuln_count = 0

        self.ai = AIClient(AI_API_KEY, AI_BASE_URL, AI_MODEL, self)
        self._auto_test = AUTO_TEST

        self.logger = LoggerTab()
        callbacks.addSuiteTab(self.logger)
        callbacks.registerProxyListener(self)

        self.log("=" * 54)
        self.log("  Port Highlighter + AI Access Control Tester")
        self.log("=" * 54)
        for port in sorted(self.port_config.keys()):
            cfg = self.port_config[port]
            self.log("  Port %d -> %s (%s)" %
                     (port, cfg.get("color", "?"), cfg.get("role", "?")))
        self.log("  AI: %s" % ("enabled" if self.ai.api_key else "DISABLED"))
        self.log("  Auto-test: %s" % ("ON" if self._auto_test else "OFF"))
        self.log("  Strategy: ID SWAP (cross-port ID substitution)")
        self.log("=" * 54)

    # ── Logging ──────────────────────────────────────────────────────

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.logger.append("[%s] %s\n" % (ts, msg))
        self._callbacks.printOutput(msg)

    def log_good(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.logger.append("[%s] [+] %s\n" % (ts, msg))
        self._callbacks.printOutput("[+] " + msg)

    def log_bad(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.logger.append("[%s] [!] %s\n" % (ts, msg))
        self._callbacks.printOutput("[!] " + msg)

    def log_info(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.logger.append("[%s] [i] %s\n" % (ts, msg))

    # ── Proxy Listener ───────────────────────────────────────────────

    def processProxyMessage(self, messageIsRequest, message):
        port = _parse_port(message.getListenerInterface())
        if port is None or port not in self.port_config:
            return
        cfg = self.port_config[port]

        # Highlight ALL requests
        if messageIsRequest:
            color = cfg.get("color")
            if color:
                try:
                    message.getMessageInfo().setHighlight(color)
                except Exception:
                    pass

        # Collect IDs + cross-test (on response, when we have full picture)
        if not messageIsRequest:
            self._handle_response(port, cfg, message)

    def _handle_response(self, port, cfg, message):
        http_msg = message.getMessageInfo()
        request_bytes = http_msg.getRequest()
        response_bytes = http_msg.getResponse()
        if response_bytes is None:
            return

        self._request_count += 1

        # Track session cookies for this port
        session = _extract_cookies(request_bytes, self._helpers)
        if session:
            self._sessions[port] = session  # keep latest

        # Parse request to extract IDs
        try:
            svc = http_msg.getHttpService()
            info = self._helpers.analyzeRequest(svc, request_bytes)
            url = str(info.getUrl())
            url_path = info.getUrl().getPath() if info.getUrl() else ""
            query = info.getUrl().getQuery() if info.getUrl() else ""
            query = query if query else ""
            body_offset = info.getBodyOffset()
            body = request_bytes[body_offset:].tostring() if body_offset < len(request_bytes) else ""
        except Exception:
            return

        # Extract IDs
        ids = _extract_ids(url_path, query, body)
        if not ids:
            return

        self._id_count += 1

        # Store collected IDs per port
        if port not in self._collected_ids:
            self._collected_ids[port] = {}
        for name, val in ids:
            if len(self._collected_ids[port]) < ID_COLLECTION_CAP:
                self._collected_ids[port][val] = True

        # Auto-test: swap IDs from THIS port with IDs from OTHER ports
        if not self._auto_test:
            return

        role = cfg.get("role", "user")

        # Find IDs from other ports to swap with
        other_ids = []
        for other_port, other_cfg in self.port_config.items():
            if other_port == port:
                continue
            if other_port in self._collected_ids:
                for vid in self._collected_ids[other_port]:
                    other_ids.append((other_port, vid))

        if not other_ids:
            return

        # For each ID in this request, swap with an ID from another port
        for id_name, original_id in ids:
            for other_port, other_id in other_ids:
                if other_id == original_id:
                    continue

                dedupe_key = "%s|%s|%s|%s->%s" % (
                    info.getMethod(), url, port, original_id, other_id
                )
                if dedupe_key in self._tested:
                    continue
                self._tested.add(dedupe_key)

                # Build modified request with swapped ID
                new_path, new_query, new_body = _replace_ids(
                    url_path, query, body, original_id, other_id
                )
                mod_request = _rebuild_request(
                    self._helpers, svc, request_bytes,
                    new_path, new_query, new_body
                )
                if mod_request is None:
                    continue

                try:
                    mod_resp = self._callbacks.makeHttpRequest(
                        svc.getHost(), svc.getPort(),
                        svc.getProtocol() == "https", mod_request
                    )
                    finding = self._compare(
                        url_path, info.getMethod(), original_id, other_id,
                        port, other_port,
                        response_bytes, mod_resp
                    )
                    if finding:
                        self._findings.append(finding)
                        self._test_count += 1
                        self.log_info(
                            "  [test #%d] %s %s  ID %s:%s -> %s:%s  orig=%d swap=%d" %
                            (self._test_count, info.getMethod(), url_path,
                             id_name, original_id, id_name, other_id,
                             finding["original_status"],
                             finding["swapped_status"])
                        )
                        if len(self._findings) >= BATCH_SIZE:
                            self._run_ai()
                except Exception as e:
                    self.log_info("  [err] ID swap failed: %s" % e)

    # ── Response comparison ──────────────────────────────────────────

    def _compare(self, url_path, method, original_id, swapped_id,
                 from_port, other_port,
                 original_resp, swapped_resp):
        try:
            o_info = self._helpers.analyzeResponse(original_resp)
            s_info = self._helpers.analyzeResponse(swapped_resp)
            o_status = o_info.getStatusCode()
            s_status = s_info.getStatusCode()

            o_body_off = o_info.getBodyOffset()
            s_body_off = s_info.getBodyOffset()
            o_body = original_resp[o_body_off:].tostring() if o_body_off < len(original_resp) else ""
            s_body = swapped_resp[s_body_off:].tostring() if s_body_off < len(swapped_resp) else ""

            # Both success + different bodies = potential IDOR
            if 200 <= o_status < 400 and 200 <= s_status < 400:
                len_diff = abs(len(o_body) - len(s_body))
                max_len = max(len(o_body), len(s_body), 1)
                pct = (float(len_diff) / max_len) * 100.0

                # If bodies are substantially different, it's worth investigating
                # (we accessed different data with swapped ID)
                if pct >= MIN_CONTENT_DIFF_PCT:
                    return {
                        "url": url_path,
                        "method": method,
                        "original_id": original_id,
                        "swapped_id": swapped_id,
                        "from_port": from_port,
                        "other_port": other_port,
                        "original_status": o_status,
                        "swapped_status": s_status,
                        "original_body": o_body,
                        "swapped_body": s_body,
                        "content_diff_pct": pct,
                    }

            # Swapped gets 2xx where original got 4xx (unexpected access)
            if 200 <= s_status < 400 and o_status >= 400:
                return {
                    "url": url_path,
                    "method": method,
                    "original_id": original_id,
                    "swapped_id": swapped_id,
                    "from_port": from_port,
                    "other_port": other_port,
                    "original_status": o_status,
                    "swapped_status": s_status,
                    "original_body": o_body,
                    "swapped_body": s_body,
                    "content_diff_pct": 100.0,
                }
        except Exception:
            pass
        return None

    # ── AI ───────────────────────────────────────────────────────────

    def _run_ai(self):
        if not self._findings:
            return
        batch = self._findings[:]
        self._findings = []

        self.log("")
        self.log("[AI] Analyzing %d potential ACL issues ..." % len(batch))
        result = self.ai.analyze(batch)
        if result is None:
            self.log("[AI] Skipped (no API key). Review:")
            for f in batch:
                self.log("  - %s %s  ID %s->%s (orig=%d swap=%d)" %
                         (f["method"], f["url"],
                          f["original_id"], f["swapped_id"],
                          f["original_status"], f["swapped_status"]))
            return

        try:
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "{}")
            parsed = json.loads(content)
            self._report(batch, parsed.get("findings", []))
        except Exception as e:
            self.log("[AI] Parse error: %s" % e)

    def _report(self, raw, ai_results):
        for i, ai in enumerate(ai_results):
            if i >= len(raw):
                break
            if not ai.get("vulnerable"):
                continue
            f = raw[i]
            self._vuln_count += 1
            sev = ai.get("severity", "?").upper()
            self.log("")
            self.log("=" * 54)
            self.log_bad("[%s] %s" % (sev, ai.get("title", "ACL Issue")))
            self.log("  URL:      %s" % f["url"])
            self.log("  Method:   %s" % f["method"])
            self.log("  ID swap:  %s:%d -> %s:%d" %
                     (f["from_port"], int(f["original_id"]) if f["original_id"].isdigit() else f["original_id"],
                      f["other_port"], int(f["swapped_id"]) if f["swapped_id"].isdigit() else f["swapped_id"]))
            self.log("  Orig:     %d  |  Swapped: %d" %
                     (f["original_status"], f["swapped_status"]))
            self.log("  Diff:     %.0f%%" % f.get("content_diff_pct", 0))
            self.log("  ---")
            for line in ai.get("description", "").split("\n"):
                self.log("  " + line)
            self.log("=" * 54)

    # ── Persistence ──────────────────────────────────────────────────

    def _load_config(self):
        raw = self._callbacks.loadExtensionSetting("port_highlighter.mappings")
        if raw:
            try:
                data = json.loads(raw)
                for port_str, val in data.items():
                    port = int(port_str)
                    if isinstance(val, dict):
                        self.port_config[port] = val
                    else:
                        self.port_config[port] = {"color": val, "role": "user"}
            except Exception:
                pass
