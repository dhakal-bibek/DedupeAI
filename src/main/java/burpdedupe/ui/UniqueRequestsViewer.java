package burpdedupe.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burpdedupe.proxy.DedupeProxyHandler;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.WindowConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A standalone window that lists <em>only the unique</em> requests from a selection,
 * styled to mirror Burp's HTTP-history table (same kind of columns, a Notes column
 * carrying our {@code [DEDUPE] …} verdict + {@code [attacker]/[victim] port N} tag, and
 * rows tinted by their Burp highlight colour). Read-only request/response viewers sit
 * beneath the table.
 *
 * <p>The toolbar has <b>Send to Repeater</b>, <b>Save</b>, a <b>Magic Cookie</b> action
 * (reissue the selection with a user-supplied auth set swapped in — for same-request,
 * different-identity IDOR/BOLA checks), and a <b>filter</b> box that
 * matches across all columns (substring, or a regular expression when "regex" is
 * ticked). Full Bambda (Java-snippet) filtering isn't possible from an extension —
 * Montoya only exposes {@code bambda().importBambda(...)} to load a Bambda into Burp,
 * not to evaluate one — so this is a fast text/regex filter instead.
 *
 * <p>Must be constructed on the Swing EDT — it creates Montoya editor components.
 */
final class UniqueRequestsViewer {

    private final MontoyaApi api;
    private final List<HttpRequestResponse> uniques;
    private final String baseTitle;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final UniqueTableModel model;
    private final JTable table;
    private final JFrame frame;
    private final TableRowSorter<UniqueTableModel> sorter;
    private final JTextField filterField = new JTextField(26);
    private final JCheckBox regexBox = new JCheckBox("regex");
    private final JLabel status = new JLabel(" ");
    /** Live mode: ids of Proxy-history entries already collected (so polling never re-adds one). */
    private final Set<Integer> seenIds = new HashSet<>();
    private final AtomicBoolean polling = new AtomicBoolean(false);
    private Timer liveTimer;

    /** Live export: mirror every collected unique request to a file Claude Code can read. */
    private final JCheckBox cbLiveExport = new JCheckBox("Live export → file", false);
    private Timer exportDebounce;
    private static final Object EXPORT_LOCK = new Object();

    UniqueRequestsViewer(MontoyaApi api, List<HttpRequestResponse> uniques) {
        this(api, uniques, "Unique requests");
    }

    /** @param title the window subtitle, e.g. "Unique requests" or "Magic Cookie results". */
    UniqueRequestsViewer(MontoyaApi api, List<HttpRequestResponse> uniques, String title) {
        this.api = api;
        this.uniques = new ArrayList<>(uniques);
        this.baseTitle = title;
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        this.model = new UniqueTableModel(this.uniques);
        this.table = new JTable(model);
        this.sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);   // fixed widths + horizontal scroll, like Burp
        table.setDefaultRenderer(Object.class, new HighlightRenderer(model));
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow >= 0) showRow(table.convertRowIndexToModel(viewRow));
            scheduleLiveExport(); // refresh selection.http on selection change
        });
        applyColumnWidths(table);

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editors.setResizeWeight(0.5);

        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), editors);
        main.setResizeWeight(0.35);

        status.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        JPanel root = new JPanel(new BorderLayout());
        root.add(buildToolbar(), BorderLayout.NORTH);
        root.add(main, BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH);

        this.frame = new JFrame("Dedupe — " + baseTitle + " (" + this.uniques.size() + ")");
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        frame.add(root);
        frame.setSize(1150, 760);
        frame.setLocationRelativeTo(null);
        api.userInterface().applyThemeToComponent(frame.getRootPane());

        if (!this.uniques.isEmpty()) {
            table.setRowSelectionInterval(0, 0); // shows the first request immediately
        }
        updateCount();
        frame.setVisible(true);
    }

    private JPanel buildToolbar() {
        JButton repeater = new JButton("Send to Repeater");
        repeater.setToolTipText("Send the selected request(s) to new Repeater tabs (named by method + path).");
        repeater.addActionListener(e -> sendSelectedToRepeater());

        JButton save = new JButton("Save request(s)");
        save.setToolTipText("Save the selected request(s) and their responses into one .http file. "
                + "Ctrl/Cmd- or Shift-click to select several.");
        save.addActionListener(e -> saveSelectedRequests());

        JButton magic = new JButton("Magic Cookie");
        magic.setToolTipText("Resend the selected request(s) with your configured auth replacing the "
                + "original Cookie / Authorization (and any header you list); everything else unchanged. "
                + "Opens the results in a new window.");
        magic.addActionListener(e -> openMagicCookieDialog());

        JButton matchReplace = new JButton("Match & Replace");
        matchReplace.setToolTipText("IDOR/BOLA: replace an id or token in the path/query, body, or both, "
                + "then reissue the selected request(s) — watch the live results for an unexpected 200.");
        matchReplace.addActionListener(e -> openMatchReplaceDialog());

        JButton clear = new JButton("Clear");
        clear.setToolTipText("Empty this window — clears the collected rows. "
                + "(In the live window, new [DEDUPE] UNIQUE requests keep arriving after.)");
        clear.addActionListener(e -> clearView());

        Path exportDir = exportDir();
        cbLiveExport.setToolTipText("<html>Auto-writes to <code>" + exportDir + "</code>:<br>"
                + "• <b>live-unique.http</b> — every unique request, as it arrives<br>"
                + "• <b>selection.http</b> — your current selection, as you change it<br>"
                + "Point Claude Code at either path. On by default in the live window; untick to stop.</html>");
        cbLiveExport.addActionListener(e -> { if (cbLiveExport.isSelected()) scheduleLiveExport(); });
        api.logging().logToOutput("[burp-dedupe] live export dir: " + exportDir + " (live-unique.http, selection.http)");

        filterField.setToolTipText("Filter rows across all columns (Host / Method / URL / Status / MIME / Notes). "
                + "Plain substring; tick 'regex' for a regular expression.");
        filterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void removeUpdate(DocumentEvent e) { applyFilter(); }
            @Override public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        regexBox.setToolTipText("Treat the filter text as a regular expression (case-insensitive).");
        regexBox.addItemListener(e -> applyFilter());

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        bar.add(repeater);
        bar.add(save);
        bar.add(magic);
        bar.add(matchReplace);
        bar.add(clear);
        bar.add(cbLiveExport);
        bar.add(new JLabel("    Filter:"));
        bar.add(filterField);
        bar.add(regexBox);
        return bar;
    }

    /** Filters the table across all columns: substring by default, regex when ticked. Case-insensitive. */
    private void applyFilter() {
        String text = filterField.getText();
        if (text == null || text.isEmpty()) {
            sorter.setRowFilter(null);
            updateCount();
            return;
        }
        try {
            String regex = regexBox.isSelected() ? text : Pattern.quote(text);
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + regex));
            updateCount();
        } catch (PatternSyntaxException ex) {
            status.setText("Invalid regex: " + ex.getMessage());
        }
    }

    private void updateCount() {
        status.setText("Showing " + table.getRowCount() + " of " + uniques.size() + " request(s).");
    }

    /**
     * Appends one streamed result and refreshes the table live — must be called on the EDT. The
     * Magic Cookie flow opens this window immediately (empty) and calls this as each response
     * returns, so rows appear one by one instead of all at once when the batch finishes.
     */
    void addResult(HttpRequestResponse rr) {
        if (rr == null) return;
        int idx = uniques.size();
        uniques.add(rr);
        model.fireTableRowsInserted(idx, idx);
        frame.setTitle("Dedupe — " + baseTitle + " (" + uniques.size() + ")");
        if (uniques.size() == 1) {
            table.setRowSelectionInterval(0, 0); // show the first response the moment it lands
        }
        updateCount();
        scheduleLiveExport();
    }

    /** Bulk-appends rows with a single table refresh (EDT only). Used by the live back-fill. */
    void addResults(List<HttpRequestResponse> rows) {
        if (rows == null || rows.isEmpty()) return;
        int start = uniques.size();
        uniques.addAll(rows);
        model.fireTableRowsInserted(start, uniques.size() - 1);
        frame.setTitle("Dedupe — " + baseTitle + " (" + uniques.size() + ")");
        if (start == 0) {
            table.setRowSelectionInterval(0, 0);
        }
        updateCount();
        scheduleLiveExport();
    }

    /** Routes an event line to Burp's extension output (the in-window live log was removed). */
    void log(String line) {
        api.logging().logToOutput("[burp-dedupe] " + line);
    }

    /**
     * Empties the table. In live mode {@code seenIds} is kept, so cleared rows don't reappear on the
     * next poll — only genuinely new {@code [DEDUPE] UNIQUE} entries arrive.
     */
    private void clearView() {
        int n = uniques.size();
        uniques.clear();
        model.fireTableDataChanged();
        frame.setTitle("Dedupe — " + baseTitle + " (0)");
        status.setText("Cleared " + n + " row(s).");
        scheduleLiveExport();
    }

    // ── Live feed: auto-collect HTTP-history rows marked [DEDUPE] UNIQUE ──────

    /**
     * Opens a <b>live</b> window that automatically collects every Proxy HTTP-history entry the
     * extension has marked <code>[DEDUPE] UNIQUE</code> in its Notes — and only those. It polls the
     * history (~1s) so new uniques appear on their own as you browse; the duplicates Burp already
     * folded away (<code>[DEDUPE] DUPE …</code>) never show, and uniques already in history are
     * collected the moment you open it. Closing the window stops the polling.
     *
     * <p>This re-reads the verdict the proxy handler already wrote — it does <em>not</em> recompute
     * signatures — so keep verdict stamping on (that's what writes the note). Must be called on the
     * Swing EDT.
     */
    static UniqueRequestsViewer openLive(MontoyaApi api) {
        UniqueRequestsViewer viewer = new UniqueRequestsViewer(api, new ArrayList<>(), "Live unique history");
        viewer.startLivePolling();
        return viewer;
    }

    private void startLivePolling() {
        log("Live unique history — auto-collecting [DEDUPE] UNIQUE entries from HTTP history…");
        cbLiveExport.setSelected(true);  // the live window auto-exports every unique by default
        scheduleLiveExport();            // create the (initially empty) export file right away
        liveTimer = new Timer(1000, e -> pollHistory());
        liveTimer.setRepeats(true);
        liveTimer.start();
        pollHistory(); // immediate first pass picks up the uniques already in history

        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent e) {
                if (liveTimer != null) liveTimer.stop();
            }
        });
    }

    /**
     * Appends any Proxy-history entry whose Notes start with {@code [DEDUPE] UNIQUE} that we haven't
     * already collected. Re-scans the whole history each tick (cheap) so it also catches entries the
     * "Stamp existing history" pass marks unique <em>after</em> the window is open. Runs off the EDT
     * and never overlaps itself.
     */
    private void pollHistory() {
        if (!polling.compareAndSet(false, true)) return; // a scan is already in flight
        Thread t = new Thread(() -> {
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                List<HttpRequestResponse> batch = new ArrayList<>();
                for (ProxyHttpRequestResponse h : history) {
                    if (h == null || h.request() == null) continue;
                    if (seenIds.contains(h.id())) continue;          // already collected
                    if (!isDedupeUnique(h.annotations())) continue;  // not (yet) a [DEDUPE] UNIQUE row
                    seenIds.add(h.id());
                    HttpResponse resp = h.hasResponse() && h.response() != null ? h.response() : HttpResponse.httpResponse();
                    batch.add(HttpRequestResponse.httpRequestResponse(h.request(), resp, h.annotations()));
                }
                if (!batch.isEmpty()) {
                    SwingUtilities.invokeLater(() -> {
                        addResults(batch);
                        if (batch.size() <= 12) {
                            for (HttpRequestResponse rr : batch) log("UNIQUE  " + safeReqLine(rr.request()));
                        } else {
                            log("Added " + batch.size() + " [DEDUPE] UNIQUE from history.");
                        }
                    });
                }
            } catch (RuntimeException ex) {
                api.logging().logToError("[burp-dedupe] live history poll failed: " + ex);
            } finally {
                polling.set(false);
            }
        }, "burp-dedupe-live-poll");
        t.setDaemon(true);
        t.start();
    }

    /** True iff these annotations' Notes start with {@code [DEDUPE] UNIQUE}. */
    private static boolean isDedupeUnique(Annotations a) {
        try {
            if (a == null || !a.hasNotes()) return false;
            String notes = a.notes();
            return notes != null && notes.startsWith(DedupeProxyHandler.NOTE_PREFIX + " UNIQUE");
        } catch (RuntimeException e) {
            return false;
        }
    }

    private void showRow(int modelRow) {
        if (modelRow < 0 || modelRow >= uniques.size()) return;
        HttpRequestResponse rr = uniques.get(modelRow);
        requestEditor.setRequest(rr.request());
        responseEditor.setResponse(
                rr.hasResponse() && rr.response() != null ? rr.response() : HttpResponse.httpResponse());
    }

    /** All currently selected rows (in view order), skipping nulls. Empty if nothing is selected. */
    private List<HttpRequestResponse> selectedRows() {
        int[] viewRows = table.getSelectedRows();
        List<HttpRequestResponse> out = new ArrayList<>(viewRows.length);
        for (int vr : viewRows) {
            HttpRequestResponse rr = uniques.get(table.convertRowIndexToModel(vr));
            if (rr != null) out.add(rr);
        }
        return out;
    }

    /** Sends each selected request to a new Repeater tab, named by its method + path. */
    private void sendSelectedToRepeater() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }
        int sent = 0;
        try {
            for (HttpRequestResponse rr : sel) {
                HttpRequest req = rr.request();
                if (req == null) continue;
                api.repeater().sendToRepeater(req, repeaterCaption(req));
                sent++;
            }
            status.setText("Sent " + sent + " request(s) to Repeater.");
            log("Sent " + sent + " request(s) to Repeater.");
        } catch (RuntimeException ex) {
            api.logging().logToError("[burp-dedupe] send-to-Repeater failed: " + ex);
            status.setText("Sent " + sent + " then failed: " + ex.getMessage());
            log("Send to Repeater failed after " + sent + ": " + ex.getMessage());
        }
    }

    /** Repeater tab caption from the request, e.g. {@code "GET /test/lasd/something/234"}. */
    private static String repeaterCaption(HttpRequest req) {
        String caption = (safe(req::method) + " " + safe(req::path)).trim();
        if (caption.isEmpty()) return "dedupe";
        return caption.length() > 80 ? caption.substring(0, 80) : caption;
    }

    /** Saves all selected requests (and their responses) into one .http file the user chooses. */
    private void saveSelectedRequests() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save " + sel.size() + " request(s) to one .http file");
        chooser.setCurrentDirectory(new File(System.getProperty("user.home", ".")));
        String defName = sel.size() == 1 ? suggestFileName(sel.get(0).request()) : "requests-" + sel.size() + ".http";
        chooser.setSelectedFile(new File(defName));
        if (chooser.showSaveDialog(table) != JFileChooser.APPROVE_OPTION) return;

        File target = chooser.getSelectedFile();
        try {
            Files.writeString(target.toPath(), buildHttpDump(sel), StandardCharsets.UTF_8);
            status.setText("Saved " + sel.size() + " request(s) to " + target.getAbsolutePath());
            api.logging().logToOutput("[burp-dedupe] saved " + sel.size() + " request(s) to " + target.getAbsolutePath());
            log("Saved " + sel.size() + " request(s) to " + target.getName());
        } catch (IOException ex) {
            api.logging().logToError("[burp-dedupe] save requests failed: " + ex);
            status.setText("Save failed: " + ex.getMessage());
            log("Save failed: " + ex.getMessage());
        }
    }

    // ── Magic Cookie: reissue the selection with a swapped-in auth set ────────

    private static final String PREF_MAGIC_COOKIE = "burp-dedupe.magic-cookie.headers";

    /** Shown until an auth set is saved. Parses to zero headers (every line is a comment). */
    private static final String DEFAULT_MAGIC_HINT =
            "# Paste the auth headers to send with — one per line, as  Name: value\n"
          + "# They replace the request's Cookie / Authorization (and any header you list);\n"
          + "# everything else is sent unchanged. Lines starting with # are ignored.\n"
          + "#\n"
          + "# Cookie: session=...\n"
          + "# Authorization: Bearer ...\n";

    /**
     * Opens the Magic Cookie editor for the current selection. The user supplies a set of auth
     * headers (remembered across windows/restarts via Montoya preferences); on send, each selected
     * request is reissued with that auth swapped in — see {@link #applyMagicCookie} — and the
     * results open in their own window so original vs. swapped-identity responses can be compared.
     */
    private void openMagicCookieDialog() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }

        Preferences prefs = api.persistence().preferences();
        String saved = prefs.getString(PREF_MAGIC_COOKIE);

        JTextArea area = new JTextArea(saved == null || saved.isBlank() ? DEFAULT_MAGIC_HINT : saved, 11, 52);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setLineWrap(false);

        JLabel help = new JLabel("<html>One header per line — <b>Name: value</b>. These replace the "
                + "request's <b>Cookie</b> and <b>Authorization</b> (and any header you list); everything "
                + "else is sent unchanged.</html>");
        help.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(table),
                "Magic Cookie — replace auth, then send");
        dialog.setModal(true);

        JButton send = new JButton("Send " + sel.size() + " request(s)");
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(ev -> dialog.dispose());
        send.addActionListener(ev -> {
            List<HttpHeader> headers = parseHeaders(area.getText());
            if (headers.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Enter at least one auth header (Name: value).",
                        "Magic Cookie", JOptionPane.WARNING_MESSAGE);
                return;
            }
            prefs.setString(PREF_MAGIC_COOKIE, area.getText());
            dialog.dispose();
            sendWithMagicCookie(sel, headers);
        });

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.add(cancel);
        buttons.add(send);

        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(help, BorderLayout.NORTH);
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.getRootPane().setDefaultButton(send);
        api.userInterface().applyThemeToComponent(dialog.getRootPane());
        dialog.pack();
        dialog.setLocationRelativeTo(table);
        dialog.setVisible(true);
    }

    private void sendWithMagicCookie(List<HttpRequestResponse> selected, List<HttpHeader> headers) {
        StringBuilder names = new StringBuilder();
        for (HttpHeader h : headers) names.append(names.length() == 0 ? "" : ", ").append(h.name());
        streamReissue(selected, "Magic Cookie results",
                req -> applyMagicCookie(req, headers),
                "Magic Cookie — swapping auth (" + names + ") into " + selected.size() + " request(s)");
    }

    /**
     * Shared engine for the "reissue the selection with a per-request transform, stream results
     * live" actions (Magic Cookie, Match &amp; Replace). The results window opens <em>immediately</em>
     * (empty); each response is appended to its table as it returns, rather than all at once when the
     * batch finishes.
     *
     * <p>Requests go out via Burp's HTTP client ({@code api.http().sendRequest}), so they appear in
     * Logger, not Proxy history.
     */
    private void streamReissue(List<HttpRequestResponse> selected, String resultTitle,
                               UnaryOperator<HttpRequest> transform, String intro) {
        List<HttpRequestResponse> snapshot = new ArrayList<>(selected);
        status.setText(resultTitle + ": sending " + snapshot.size() + " request(s)…");

        // Open the live results window now (on the EDT); the worker feeds rows + log lines in live.
        UniqueRequestsViewer results = new UniqueRequestsViewer(api, new ArrayList<>(), resultTitle);
        results.log(intro);

        Thread t = new Thread(() -> {
            int sent = 0, failed = 0, skipped = 0;
            for (HttpRequestResponse rr : snapshot) {
                HttpRequest req = rr == null ? null : rr.request();
                if (req == null) { failed++; continue; }
                try {
                    // A transform that returns null means "nothing to change here" — e.g. the match
                    // id isn't in this request — so we don't reissue it. Only requests that actually
                    // changed are sent and shown.
                    HttpRequest modified = transform.apply(req);
                    if (modified == null) {
                        skipped++;
                    } else {
                        HttpRequestResponse out = api.http().sendRequest(modified);
                        results.log(logLine(modified, out));
                        SwingUtilities.invokeLater(() -> results.addResult(out)); // live: append as it lands
                        sent++;
                    }
                } catch (RuntimeException ex) {
                    results.log("ERROR  " + safeReqLine(req) + " — " + ex.getMessage());
                    api.logging().logToError("[burp-dedupe] " + resultTitle + " send failed: " + ex);
                    failed++;
                }
                final int s = sent, f = failed, sk = skipped;
                SwingUtilities.invokeLater(() -> status.setText(resultTitle + ": sent " + s
                        + (sk > 0 ? ", " + sk + " skipped" : "") + (f > 0 ? ", " + f + " failed" : "")
                        + " of " + snapshot.size() + "…"));
            }
            final int s = sent, f = failed, sk = skipped;
            results.log("done — sent " + s + (sk > 0 ? ", " + sk + " skipped (no match)" : "")
                    + (f > 0 ? ", " + f + " failed" : ""));
            SwingUtilities.invokeLater(() -> {
                status.setText(resultTitle + ": sent " + s + (sk > 0 ? ", " + sk + " skipped" : "")
                        + (f > 0 ? ", " + f + " failed" : "") + ".");
                api.logging().logToOutput("[burp-dedupe] " + resultTitle + " — sent " + s
                        + " skipped " + sk + " failed " + f);
            });
        }, "burp-dedupe-reissue");
        t.setDaemon(true);
        t.start();
    }

    /** One output line: the (possibly modified) request line, then the response status + length. */
    private static String logLine(HttpRequest req, HttpRequestResponse out) {
        String resp = (out != null && out.hasResponse() && out.response() != null)
                ? out.response().statusCode() + "  " + out.response().body().length() + "b"
                : "(no response)";
        return safeReqLine(req) + "   ←   " + resp;
    }

    private static String safeReqLine(HttpRequest req) {
        return (safe(req::method) + " " + safe(req::path)).trim();
    }

    /**
     * Returns {@code req} with its auth replaced by {@code headers}: the standard credential
     * carriers (Cookie, Authorization) and any header named in {@code headers} are removed first,
     * then the supplied headers are added — so the request goes out with only those credentials.
     * Method, path, body and every other header are left untouched.
     */
    private static HttpRequest applyMagicCookie(HttpRequest req, List<HttpHeader> headers) {
        Set<String> strip = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        strip.add("Cookie");
        strip.add("Authorization");
        for (HttpHeader h : headers) strip.add(h.name());

        HttpRequest out = req;
        for (String name : strip) {
            if (out.hasHeader(name)) out = out.withRemovedHeader(name);
        }
        for (HttpHeader h : headers) {
            out = out.withAddedHeader(h.name(), h.value());
        }
        return out;
    }

    /** Parses {@code Name: value} lines into headers (order preserved); blanks and #-comments skipped. */
    private static List<HttpHeader> parseHeaders(String text) {
        List<HttpHeader> out = new ArrayList<>();
        if (text == null) return out;
        for (String raw : text.split("\\R")) {
            String line = raw.strip();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int colon = line.indexOf(':');
            if (colon <= 0) continue;                 // need a name before the colon
            String name = line.substring(0, colon).strip();
            String value = line.substring(colon + 1).strip();
            if (!name.isEmpty()) out.add(HttpHeader.httpHeader(name, value));
        }
        return out;
    }

    // ── Match & Replace (IDOR/BOLA): swap an id/token in path/body, then reissue ──

    private static final String PREF_MR_MATCH   = "burp-dedupe.match-replace.match";
    private static final String PREF_MR_REPLACE = "burp-dedupe.match-replace.replace";
    private static final String PREF_MR_PATH    = "burp-dedupe.match-replace.path";
    private static final String PREF_MR_BODY    = "burp-dedupe.match-replace.body";
    private static final String PREF_MR_REGEX   = "burp-dedupe.match-replace.regex";

    /**
     * Opens the Match &amp; Replace editor for the current selection — built for IDOR/BOLA: enter the
     * object id (or any token) to find and what to swap it for, choose whether to apply it to the
     * <b>path/query</b>, the <b>body</b>, or both, then reissue. Each reissued request streams into a
     * live results window (table + log) so an unexpected {@code 200} stands out. Settings are
     * remembered across windows/restarts via Montoya preferences.
     */
    private void openMatchReplaceDialog() {
        List<HttpRequestResponse> sel = selectedRows();
        if (sel.isEmpty()) { status.setText("Select one or more requests first."); return; }

        Preferences prefs = api.persistence().preferences();
        JTextField matchField = new JTextField(orEmpty(prefs.getString(PREF_MR_MATCH)), 22);
        JTextField replaceField = new JTextField(orEmpty(prefs.getString(PREF_MR_REPLACE)), 22);
        JCheckBox cbPath = new JCheckBox("Path / query", boolDefault(prefs.getBoolean(PREF_MR_PATH), true));
        JCheckBox cbBody = new JCheckBox("Body", boolDefault(prefs.getBoolean(PREF_MR_BODY), true));
        JCheckBox cbRegex = new JCheckBox("regex", boolDefault(prefs.getBoolean(PREF_MR_REGEX), false));

        JLabel help = new JLabel("<html>For <b>IDOR / BOLA</b>: replace an object id (or any token) in the "
                + "request's <b>path/query</b>, <b>body</b>, or both, then reissue. <b>Only requests that "
                + "actually contain the match are sent</b> (the rest are skipped); within each, everything "
                + "but the matched value is left unchanged. Watch the results for a <b>200</b> where another "
                + "identity's value should be denied.</html>");
        help.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 2, 2, 2);
        g.anchor = GridBagConstraints.WEST;
        g.gridx = 0; g.gridy = 0; form.add(new JLabel("Match:"), g);
        g.gridx = 1; g.weightx = 1; g.fill = GridBagConstraints.HORIZONTAL; form.add(matchField, g);
        g.gridx = 0; g.gridy = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE; form.add(new JLabel("Replace:"), g);
        g.gridx = 1; g.weightx = 1; g.fill = GridBagConstraints.HORIZONTAL; form.add(replaceField, g);
        g.gridx = 0; g.gridy = 2; g.weightx = 0; g.fill = GridBagConstraints.NONE; form.add(new JLabel("Apply to:"), g);
        JPanel scope = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        scope.add(cbPath); scope.add(cbBody); scope.add(cbRegex);
        g.gridx = 1; form.add(scope, g);

        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(table), "Match & Replace — IDOR");
        dialog.setModal(true);

        JButton send = new JButton("Replace & send " + sel.size() + " request(s)");
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(ev -> dialog.dispose());
        send.addActionListener(ev -> {
            String match = matchField.getText();
            if (match == null || match.isEmpty()) { warn(dialog, "Enter the text to match."); return; }
            boolean inPath = cbPath.isSelected();
            boolean inBody = cbBody.isSelected();
            if (!inPath && !inBody) { warn(dialog, "Pick at least one of Path/query or Body."); return; }
            boolean regex = cbRegex.isSelected();
            if (regex) {
                try { Pattern.compile(match); }
                catch (PatternSyntaxException ex) { warn(dialog, "Invalid regex: " + ex.getMessage()); return; }
            }
            String replace = replaceField.getText() == null ? "" : replaceField.getText();

            prefs.setString(PREF_MR_MATCH, match);
            prefs.setString(PREF_MR_REPLACE, replace);
            prefs.setBoolean(PREF_MR_PATH, inPath);
            prefs.setBoolean(PREF_MR_BODY, inBody);
            prefs.setBoolean(PREF_MR_REGEX, regex);
            dialog.dispose();

            String scopeLabel = (inPath && inBody) ? "path+body" : inPath ? "path/query" : "body";
            streamReissue(sel, "Match & Replace results",
                    req -> applyMatchReplace(req, match, replace, inPath, inBody, regex),
                    "Match & Replace — \"" + match + "\" -> \"" + replace + "\" in " + scopeLabel
                            + (regex ? " (regex)" : "") + " across " + sel.size() + " request(s)");
        });

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.add(cancel);
        buttons.add(send);

        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(help, BorderLayout.NORTH);
        panel.add(form, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);

        dialog.setContentPane(panel);
        dialog.getRootPane().setDefaultButton(send);
        api.userInterface().applyThemeToComponent(dialog.getRootPane());
        dialog.pack();
        dialog.setLocationRelativeTo(table);
        dialog.setVisible(true);
    }

    /**
     * Returns {@code req} with {@code match}→{@code replace} applied to the selected parts: the
     * path (which in Montoya includes the query string) and/or the body. Literal by default, or
     * regex when {@code regex} is set; {@link HttpRequest#withBody(String)} refreshes Content-Length.
     *
     * <p>Returns {@code null} if the match wasn't present in any selected part — i.e. nothing
     * changed. {@link #streamReissue} skips those, so only the requests that actually carried the id
     * (and therefore had it swapped) are reissued.
     */
    private static HttpRequest applyMatchReplace(HttpRequest req, String match, String replace,
                                                 boolean inPath, boolean inBody, boolean regex) {
        HttpRequest out = req;
        boolean changed = false;
        if (inPath) {
            String p = req.path();
            if (p != null && !p.isEmpty()) {
                String np = regex ? p.replaceAll(match, replace) : p.replace(match, replace);
                if (!np.equals(p)) { out = out.withPath(np); changed = true; }
            }
        }
        if (inBody) {
            String b = req.bodyToString();
            if (b != null && !b.isEmpty()) {
                String nb = regex ? b.replaceAll(match, replace) : b.replace(match, replace);
                if (!nb.equals(b)) { out = out.withBody(nb); changed = true; }
            }
        }
        return changed ? out : null; // null → match absent here; streamReissue won't reissue it
    }

    private static String orEmpty(String s) { return s == null ? "" : s; }

    private static boolean boolDefault(Boolean b, boolean def) { return b == null ? def : b; }

    private static void warn(Component parent, String msg) {
        JOptionPane.showMessageDialog(parent, msg, "Match & Replace", JOptionPane.WARNING_MESSAGE);
    }

    /** Builds the multi-request {@code .http} dump (each request + response in a ####-delimited section). */
    private static String buildHttpDump(List<HttpRequestResponse> rrs) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (HttpRequestResponse rr : rrs) {
            if (rr == null || rr.request() == null) continue;
            HttpRequest req = rr.request();
            n++;
            sb.append("######################## #").append(n).append("  ")
                    .append(safe(req::method)).append(' ').append(safe(req::url));
            if (rr.hasResponse() && rr.response() != null) {
                sb.append("  -> ").append(safe(() -> Short.toString(rr.response().statusCode())));
            }
            sb.append(" ########################\n");
            sb.append("===== REQUEST =====\n").append(safe(() -> req.toByteArray().toString()));
            if (rr.hasResponse() && rr.response() != null) {
                sb.append("\n\n===== RESPONSE =====\n").append(safe(() -> rr.response().toByteArray().toString()));
            }
            sb.append("\n\n");
        }
        return sb.toString();
    }

    // ── Live export: mirror the current selection to ~/.burp-dedupe/<project>/selection.http ──

    /** (Re)schedules a debounced export so rapid selection changes coalesce into a single write. */
    private void scheduleLiveExport() {
        if (!cbLiveExport.isSelected()) return;
        if (exportDebounce == null) {
            exportDebounce = new Timer(300, e -> liveExportNow());
            exportDebounce.setRepeats(false);
        }
        exportDebounce.restart();
    }

    /**
     * Writes two files in the project's export dir (off the EDT): {@code live-unique.http} = every
     * collected unique request, and {@code selection.http} = the current selection.
     */
    private void liveExportNow() {
        if (!cbLiveExport.isSelected()) return;
        List<HttpRequestResponse> all = new ArrayList<>(uniques); // every collected unique (EDT)
        List<HttpRequestResponse> sel = selectedRows();           // current selection (EDT)
        Path dir = exportDir();
        String project = exportProjectName();
        String ts = java.time.LocalTime.now().withNano(0).toString();
        Thread t = new Thread(() -> {
            try {
                synchronized (EXPORT_LOCK) {
                    Files.createDirectories(dir);
                    writeExport(dir.resolve("live-unique.http"),
                            "# burp-dedupe live export — project: " + project + " — " + ts + " — "
                                    + all.size() + " unique request(s)\n\n", all, "no requests yet");
                    writeExport(dir.resolve("selection.http"),
                            "# burp-dedupe selection — project: " + project + " — " + ts + " — "
                                    + sel.size() + " request(s)\n\n", sel, "nothing selected");
                }
                SwingUtilities.invokeLater(() -> status.setText(
                        "Live-exported " + all.size() + " unique / " + sel.size() + " selected to " + dir));
            } catch (IOException | RuntimeException ex) {
                api.logging().logToError("[burp-dedupe] live export failed: " + ex);
            }
        }, "burp-dedupe-live-export");
        t.setDaemon(true);
        t.start();
    }

    private static void writeExport(Path file, String header, List<HttpRequestResponse> rrs, String emptyNote)
            throws IOException {
        String content = rrs.isEmpty() ? header + "# (" + emptyNote + ")\n" : header + buildHttpDump(rrs);
        Files.writeString(file, content, StandardCharsets.UTF_8);
    }

    /** {@code ~/.burp-dedupe/<sanitized-project-name>/} — holds live-unique.http and selection.http. */
    private Path exportDir() {
        return Path.of(System.getProperty("user.home", "."), ".burp-dedupe", exportProjectName());
    }

    /** The current Burp project name, sanitised for use as a folder (fallback {@code "default"}). */
    private String exportProjectName() {
        String name;
        try {
            name = api.project().name();
        } catch (RuntimeException e) {
            name = null;
        }
        if (name == null || name.isBlank()) return "default";
        String safe = name.trim().replaceAll("[^a-zA-Z0-9._-]", "_");
        return safe.isBlank() ? "default" : safe;
    }

    /** A filesystem-safe default filename derived from the request's method/host/path. */
    private static String suggestFileName(HttpRequest req) {
        if (req == null) return "request.http";
        String method = safe(req::method);
        String host = safe(() -> req.httpService() != null ? req.httpService().host() : "");
        String path = safe(req::path);
        String base = (method + "_" + host + path).replaceAll("[^a-zA-Z0-9._-]", "_");
        if (base.length() > 80) base = base.substring(0, 80);
        return (base.isBlank() ? "request" : base) + ".http";
    }

    /** Null/exception-safe accessor for a String field used only in status text. */
    private static String safe(java.util.function.Supplier<String> get) {
        try {
            String v = get.get();
            return v == null ? "" : v;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static void applyColumnWidths(JTable table) {
        int[] widths = {44, 180, 70, 360, 60, 80, 110, 280}; // #, Host, Method, URL, Status, Length, MIME, Notes
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            TableColumn col = table.getColumnModel().getColumn(i);
            col.setPreferredWidth(widths[i]);
        }
    }

    /** Tints each row with its Burp highlight colour (black text), like HTTP history. */
    private static final class HighlightRenderer extends DefaultTableCellRenderer {
        private final UniqueTableModel model;

        HighlightRenderer(UniqueTableModel model) { this.model = model; }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                Color bg = awtFor(model.highlightAt(table.convertRowIndexToModel(row)));
                if (bg != null) {
                    c.setBackground(bg);
                    c.setForeground(Color.BLACK);
                } else {
                    c.setBackground(table.getBackground());
                    c.setForeground(table.getForeground());
                }
            }
            return c;
        }
    }

    /** Burp highlight colour -> a light, readable row tint. NONE -> no tint. */
    private static Color awtFor(HighlightColor h) {
        if (h == null) return null;
        return switch (h) {
            case RED     -> new Color(0xFF, 0xC8, 0xC8);
            case ORANGE  -> new Color(0xFF, 0xDD, 0xB0);
            case YELLOW  -> new Color(0xFF, 0xF6, 0xA8);
            case GREEN   -> new Color(0xC6, 0xF2, 0xC6);
            case CYAN    -> new Color(0xBF, 0xF0, 0xF0);
            case BLUE    -> new Color(0xCD, 0xD8, 0xFF);
            case PINK    -> new Color(0xFF, 0xD0, 0xE6);
            case MAGENTA -> new Color(0xF0, 0xC6, 0xF0);
            case GRAY    -> new Color(0xD8, 0xD8, 0xD8);
            case NONE    -> null;
        };
    }

    /** Burp-history-like columns. All cells are Strings so column sorting/filtering is safe. */
    private static final class UniqueTableModel extends AbstractTableModel {
        private static final String[] COLS = {"#", "Host", "Method", "URL", "Status", "Length", "MIME", "Notes"};
        private final List<HttpRequestResponse> rows;

        UniqueTableModel(List<HttpRequestResponse> rows) { this.rows = rows; }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }

        HighlightColor highlightAt(int modelRow) {
            if (modelRow < 0 || modelRow >= rows.size()) return HighlightColor.NONE;
            try {
                Annotations a = rows.get(modelRow).annotations();
                HighlightColor h = a == null ? null : a.highlightColor();
                return h == null ? HighlightColor.NONE : h;
            } catch (RuntimeException e) {
                return HighlightColor.NONE;
            }
        }

        @Override
        public Object getValueAt(int r, int c) {
            HttpRequestResponse rr = rows.get(r);
            HttpRequest req = rr.request();
            boolean hasResp = rr.hasResponse() && rr.response() != null;
            try {
                return switch (c) {
                    case 0 -> Integer.toString(r + 1);
                    case 1 -> req != null && req.httpService() != null ? req.httpService().host() : "";
                    case 2 -> req != null ? req.method() : "";
                    case 3 -> req != null ? req.path() : "";
                    case 4 -> hasResp ? Short.toString(rr.response().statusCode()) : "";
                    case 5 -> hasResp ? Integer.toString(rr.response().body().length()) : "";
                    case 6 -> hasResp ? mimeOf(rr.response()) : "";
                    case 7 -> notesOf(rr);
                    default -> "";
                };
            } catch (RuntimeException ex) {
                return "";
            }
        }

        private static String mimeOf(HttpResponse resp) {
            try {
                MimeType m = resp.mimeType();
                return m == null ? "" : m.description();
            } catch (RuntimeException e) {
                return "";
            }
        }

        private static String notesOf(HttpRequestResponse rr) {
            try {
                Annotations a = rr.annotations();
                return a != null && a.hasNotes() && a.notes() != null ? a.notes() : "";
            } catch (RuntimeException e) {
                return "";
            }
        }
    }
}
