package burpdedupe.ui;

import burp.api.montoya.MontoyaApi;
import burpdedupe.core.DedupeEngine;
import burpdedupe.core.HeaderOverrideSet;
import burpdedupe.core.SignatureConfig;
import burpdedupe.proxy.HistoryStamper;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

public final class DedupeTab {

    private static final Pattern COMMA = Pattern.compile("\\s*,\\s*");

    private final MontoyaApi api;
    private final DedupeEngine engine;
    private final AtomicBoolean enabled;
    private final AtomicBoolean colorize;
    private final AtomicBoolean preserveNotes;

    private final JComboBox<SignatureConfig.Preset> presetBox = new JComboBox<>(SignatureConfig.Preset.values());
    private final JCheckBox cbEnabled = new JCheckBox("Stamp Notes column with verdict", true);
    private final JCheckBox cbColorize = new JCheckBox("Highlight rows (yellow=unique, gray=dupe)", true);
    private final JCheckBox cbPreserve = new JCheckBox("Preserve existing notes (append after)", true);

    private final JCheckBox cbMethod = new JCheckBox("Method");
    private final JCheckBox cbScheme = new JCheckBox("Scheme");
    private final JCheckBox cbHost = new JCheckBox("Host");
    private final JCheckBox cbPort = new JCheckBox("Port");
    private final JCheckBox cbPath = new JCheckBox("Path");
    private final JCheckBox cbNormIds = new JCheckBox("Normalize numeric/UUID path segments");
    private final JCheckBox cbQNames = new JCheckBox("Query param names");
    private final JCheckBox cbQValues = new JCheckBox("Query param values");
    private final JCheckBox cbBNames = new JCheckBox("Body param names");
    private final JCheckBox cbBValues = new JCheckBox("Body param values");
    private final JCheckBox cbStatus = new JCheckBox("Response status code");
    private final JCheckBox cbCType = new JCheckBox("Response Content-Type");
    private final JCheckBox cbScope = new JCheckBox("In-scope only");
    private final JCheckBox cbStatic = new JCheckBox("Skip static assets (.css/.js/images/fonts)");
    private final JTextField tfHeaders = new JTextField();
    private final JSpinner spCap = new JSpinner(new SpinnerNumberModel(200_000, 1_000, 5_000_000, 10_000));

    private final JLabel lblTotal = new JLabel("0");
    private final JLabel lblUnique = new JLabel("0");
    private final JLabel lblDupes = new JLabel("0");
    private final JLabel lblSkipped = new JLabel("0");
    private final JLabel lblTracked = new JLabel("0");

    private final JButton btnStampHistory = new JButton("Stamp existing history");
    private final JButton btnCancelStamp = new JButton("Cancel");
    private final JCheckBox cbAutoStamp = new JCheckBox("Auto-stamp existing history when extension loads", false);
    private final JLabel lblStampStatus = new JLabel(" ");
    private final HistoryStamper stamper;
    private final AtomicBoolean stampCancel = new AtomicBoolean(false);
    private volatile Thread stampThread;

    // Header override widgets (applied only by the right-click → Dedupe → Send unique to Organizer action)
    private final JCheckBox cbOverrideEnabled = new JCheckBox("Apply header overrides when sending to Organizer", true);
    private final JRadioButton rbReplaceOrAdd = new JRadioButton("Replace if present, add if missing", true);
    private final JRadioButton rbReplaceOnly = new JRadioButton("Replace only (don't add new headers)");
    private final JTextArea taOverrideHeaders = new JTextArea(8, 40);
    private final JLabel lblOverrideStatus = new JLabel(" ");

    /** Live snapshot of the currently-applied overrides. The context menu reads this. */
    private final AtomicReference<HeaderOverrideSet> overridesRef =
            new AtomicReference<>(HeaderOverrideSet.empty());

    private final Component component;

    public DedupeTab(MontoyaApi api, DedupeEngine engine,
                     AtomicBoolean enabled, AtomicBoolean colorize, AtomicBoolean preserveNotes,
                     HistoryStamper stamper) {
        this.api = api;
        this.engine = engine;
        this.stamper = stamper;
        this.enabled = enabled;
        this.colorize = colorize;
        this.preserveNotes = preserveNotes;
        this.component = build();
        loadFromEngine(engine.config());
        applyOverrides(); // reflect initial checkbox state in the status label
        startStatsTimer();
    }

    public Component component() { return component; }

    /** Snapshot accessor for the context menu — never null, may be {@link HeaderOverrideSet#empty()}. */
    public HeaderOverrideSet currentOverrides() {
        return overridesRef.get();
    }

    private Component build() {
        JPanel root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(new EmptyBorder(12, 12, 12, 12));

        // Header
        JPanel header = new JPanel(new GridBagLayout());
        header.setBorder(titled("Behavior"));
        GridBagConstraints g = gbc();
        g.gridx = 0; g.gridy = 0; g.gridwidth = 3;
        header.add(cbEnabled, g);
        g.gridy++; header.add(cbColorize, g);
        g.gridy++; header.add(cbPreserve, g);

        g.gridy++; g.gridwidth = 1;
        header.add(new JLabel("Preset:"), g);
        g.gridx = 1; g.gridwidth = 2;
        header.add(presetBox, g);
        g.gridx = 0; g.gridy++; g.gridwidth = 1;
        header.add(new JLabel("Max tracked signatures:"), g);
        g.gridx = 1; g.gridwidth = 2;
        header.add(spCap, g);

        // Signature fields
        JPanel fields = new JPanel(new GridLayout(0, 2, 4, 2));
        fields.setBorder(titled("Signature fields"));
        fields.add(cbMethod);
        fields.add(cbScheme);
        fields.add(cbHost);
        fields.add(cbPort);
        fields.add(cbPath);
        fields.add(cbNormIds);
        fields.add(cbQNames);
        fields.add(cbQValues);
        fields.add(cbBNames);
        fields.add(cbBValues);
        fields.add(cbStatus);
        fields.add(cbCType);

        // Filters
        JPanel filters = new JPanel(new GridBagLayout());
        filters.setBorder(titled("Filters"));
        GridBagConstraints fg = gbc();
        fg.gridx = 0; fg.gridy = 0; fg.gridwidth = 2;
        filters.add(cbScope, fg);
        fg.gridy++; filters.add(cbStatic, fg);
        fg.gridy++; fg.gridwidth = 1;
        filters.add(new JLabel("Include headers (comma-sep, lowercase):"), fg);
        fg.gridx = 1;
        filters.add(tfHeaders, fg);

        // Stats
        JPanel stats = new JPanel(new GridLayout(0, 2, 4, 2));
        stats.setBorder(titled("Stats"));
        stats.add(new JLabel("Total seen:"));      stats.add(lblTotal);
        stats.add(new JLabel("Unique:"));          stats.add(lblUnique);
        stats.add(new JLabel("Duplicates:"));      stats.add(lblDupes);
        stats.add(new JLabel("Skipped:"));         stats.add(lblSkipped);
        stats.add(new JLabel("Tracked signatures:")); stats.add(lblTracked);

        // Buttons
        JButton btnApply = new JButton("Apply (resets seen-set)");
        JButton btnReset = new JButton("Reset stats");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(btnApply);
        buttons.add(btnReset);

        // History stamping
        JPanel historyPanel = new JPanel(new GridBagLayout());
        historyPanel.setBorder(titled("Existing HTTP history"));
        GridBagConstraints hg = gbc();
        hg.gridx = 0; hg.gridy = 0; hg.gridwidth = 3;
        historyPanel.add(cbAutoStamp, hg);
        hg.gridy++; hg.gridwidth = 1;
        historyPanel.add(btnStampHistory, hg);
        hg.gridx = 1;
        historyPanel.add(btnCancelStamp, hg);
        hg.gridx = 0; hg.gridy++; hg.gridwidth = 3;
        lblStampStatus.setFont(lblStampStatus.getFont().deriveFont(Font.ITALIC));
        historyPanel.add(lblStampStatus, hg);
        btnCancelStamp.setEnabled(false);

        // Header overrides
        JPanel overridesPanel = buildOverridesPanel();

        // Help
        JTextArea help = new JTextArea(
                "How to use:\n" +
                "  1. Pick a preset that matches the vuln class you're hunting and hit Apply.\n" +
                "  2. (Optional) Paste header overrides — these are applied only when sending to Organizer.\n" +
                "  3. In HTTP history, select rows (any number — duplicates are fine), right-click → Dedupe → \"Send unique to Organizer\".\n" +
                "     • Only one request per unique signature is sent.\n" +
                "     • Header overrides (if enabled) are applied to each request before it's sent.\n" +
                "  4. In Organizer, right-click items → Extensions → whatever extension you want. It will see your overridden headers.\n\n" +
                "Notes:\n" +
                "  • Uniqueness is recomputed from the current signature config at click time — stamps in HTTP history are not required.\n" +
                "  • Changing the signature config resets the seen-set so verdicts stay consistent for live stamping.\n" +
                "  • Static assets are skipped by default to keep the seen-set small.\n" +
                "  • At Max tracked signatures the engine stops adding new keys and reports OVRF to bound memory.");
        help.setEditable(false);
        help.setOpaque(false);
        help.setBorder(titled("Quick guide"));

        // Layout
        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.add(header);
        left.add(Box.createVerticalStrut(8));
        left.add(fields);
        left.add(Box.createVerticalStrut(8));
        left.add(filters);
        left.add(Box.createVerticalStrut(8));
        left.add(historyPanel);
        left.add(Box.createVerticalStrut(8));
        left.add(buttons);
        left.add(Box.createVerticalGlue());

        JPanel right = new JPanel();
        right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));
        right.add(stats);
        right.add(Box.createVerticalStrut(8));
        right.add(overridesPanel);
        right.add(Box.createVerticalStrut(8));
        right.add(help);
        right.add(Box.createVerticalGlue());

        JScrollPane rightScroll = new JScrollPane(right,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        rightScroll.setBorder(null);
        rightScroll.getVerticalScrollBar().setUnitIncrement(16);

        JScrollPane leftScroll = new JScrollPane(left,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        leftScroll.setBorder(null);
        leftScroll.getVerticalScrollBar().setUnitIncrement(16);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScroll, rightScroll);
        split.setResizeWeight(0.5);
        split.setBorder(null);
        root.add(split, BorderLayout.CENTER);

        // Wiring
        presetBox.addActionListener(e -> {
            SignatureConfig.Preset p = (SignatureConfig.Preset) presetBox.getSelectedItem();
            if (p != null && p != SignatureConfig.Preset.CUSTOM) {
                loadFromEngine(SignatureConfig.forPreset(p));
            }
        });
        btnApply.addActionListener(e -> applyToEngine());
        btnReset.addActionListener(e -> {
            engine.reset();
            api.logging().logToOutput("[burp-dedupe] stats reset");
            refreshStats();
        });
        cbEnabled.addActionListener(e -> {
            enabled.set(cbEnabled.isSelected());
            if (!cbEnabled.isSelected()) {
                // Notes turned off → strip our [DEDUPE] prefix from existing rows.
                // If colorize is also off, do both in one pass.
                startRevert(cbColorize.isSelected()
                        ? HistoryStamper.RevertMode.NOTES_ONLY
                        : HistoryStamper.RevertMode.NOTES_AND_HIGHLIGHTS);
            }
        });
        cbColorize.addActionListener(e -> {
            colorize.set(cbColorize.isSelected());
            if (!cbColorize.isSelected()) {
                // Highlight turned off → clear color on rows we marked. Don't touch notes
                // (unless notes are also off, but the notes handler will catch that).
                startRevert(HistoryStamper.RevertMode.HIGHLIGHTS_ONLY);
            }
        });
        cbPreserve.addActionListener(e -> preserveNotes.set(cbPreserve.isSelected()));

        btnStampHistory.addActionListener(e -> startHistoryStamp());
        btnCancelStamp.addActionListener(e -> stampCancel.set(true));

        // Any manual field change flips preset to CUSTOM
        Runnable markCustom = () -> {
            if (presetBox.getSelectedItem() != SignatureConfig.Preset.CUSTOM) {
                presetBox.setSelectedItem(SignatureConfig.Preset.CUSTOM);
            }
        };
        for (JCheckBox cb : new JCheckBox[]{cbMethod, cbScheme, cbHost, cbPort, cbPath, cbNormIds,
                cbQNames, cbQValues, cbBNames, cbBValues, cbStatus, cbCType, cbScope, cbStatic}) {
            cb.addItemListener(e -> markCustom.run());
        }

        return root;
    }

    private static TitledBorder titled(String t) {
        return BorderFactory.createTitledBorder(t);
    }

    private static GridBagConstraints gbc() {
        GridBagConstraints g = new GridBagConstraints();
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1.0;
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.LINE_START;
        return g;
    }

    private void loadFromEngine(SignatureConfig cfg) {
        presetBox.setSelectedItem(cfg.preset);
        cbMethod.setSelected(cfg.includeMethod);
        cbScheme.setSelected(cfg.includeScheme);
        cbHost.setSelected(cfg.includeHost);
        cbPort.setSelected(cfg.includePort);
        cbPath.setSelected(cfg.includePath);
        cbNormIds.setSelected(cfg.normalizeNumericPathSegments);
        cbQNames.setSelected(cfg.includeQueryParamNames);
        cbQValues.setSelected(cfg.includeQueryParamValues);
        cbBNames.setSelected(cfg.includeBodyParamNames);
        cbBValues.setSelected(cfg.includeBodyParamValues);
        cbStatus.setSelected(cfg.includeStatusCode);
        cbCType.setSelected(cfg.includeContentType);
        cbScope.setSelected(cfg.inScopeOnly);
        cbStatic.setSelected(cfg.skipStatic);
        tfHeaders.setText(String.join(", ", cfg.includeHeaders));
    }

    private void applyToEngine() {
        Set<String> headers = new LinkedHashSet<>();
        String raw = tfHeaders.getText().trim();
        if (!raw.isEmpty()) {
            for (String h : COMMA.split(raw)) {
                if (!h.isEmpty()) headers.add(h.toLowerCase());
            }
        }
        SignatureConfig.Preset preset = (SignatureConfig.Preset) presetBox.getSelectedItem();
        SignatureConfig next = new SignatureConfig.Builder()
                .preset(preset == null ? SignatureConfig.Preset.CUSTOM : preset)
                .includeMethod(cbMethod.isSelected())
                .includeScheme(cbScheme.isSelected())
                .includeHost(cbHost.isSelected())
                .includePort(cbPort.isSelected())
                .includePath(cbPath.isSelected())
                .normalizeNumericPathSegments(cbNormIds.isSelected())
                .includeQueryParamNames(cbQNames.isSelected())
                .includeQueryParamValues(cbQValues.isSelected())
                .includeBodyParamNames(cbBNames.isSelected())
                .includeBodyParamValues(cbBValues.isSelected())
                .includeStatusCode(cbStatus.isSelected())
                .includeContentType(cbCType.isSelected())
                .inScopeOnly(cbScope.isSelected())
                .skipStatic(cbStatic.isSelected())
                .includeHeaders(headers)
                .build();
        engine.updateConfig(next);
        engine.setSeenCap(((Number) spCap.getValue()).intValue());
        api.logging().logToOutput("[burp-dedupe] config applied; seen-set cleared");
        refreshStats();
    }

    private void startStatsTimer() {
        Timer t = new Timer(1000, e -> refreshStats());
        t.setRepeats(true);
        t.start();
    }

    private void refreshStats() {
        lblTotal.setText(Long.toString(engine.totalSeen()));
        lblUnique.setText(Long.toString(engine.uniqueCount()));
        lblDupes.setText(Long.toString(engine.dupeCount()));
        lblSkipped.setText(Long.toString(engine.skippedCount()));
        lblTracked.setText(engine.trackedKeys() + " / " + engine.seenCap());
    }

    /** Public entry point so the extension can auto-trigger at load time. */
    public boolean isAutoStampEnabled() {
        return cbAutoStamp.isSelected();
    }

    private void startRevert(HistoryStamper.RevertMode mode) {
        if (stampThread != null && stampThread.isAlive()) {
            // Don't trample an in-progress stamp/revert. The user can toggle again later
            // once it settles. Quietly skipping is the safest option.
            api.logging().logToOutput("[burp-dedupe] revert skipped — a stamp/revert is in progress");
            return;
        }
        stampCancel.set(false);
        btnStampHistory.setEnabled(false);
        btnCancelStamp.setEnabled(true);
        String label = switch (mode) {
            case NOTES_ONLY -> "notes";
            case HIGHLIGHTS_ONLY -> "highlights";
            case NOTES_AND_HIGHLIGHTS -> "notes + highlights";
        };
        lblStampStatus.setText("Reverting " + label + "…");
        api.logging().logToOutput("[burp-dedupe] reverting " + label + " on existing history");

        stampThread = stamper.revertAsync(mode, stampCancel, new HistoryStamper.Progress() {
            @Override
            public void onProgress(int done, int total, DedupeEngine.Result lastResult) {
                SwingUtilities.invokeLater(() ->
                        lblStampStatus.setText("Reverting " + done + " / " + total + "…"));
            }
            @Override
            public void onFinished(int totalProcessed, int touched, int skipped, boolean cancelled) {
                SwingUtilities.invokeLater(() -> {
                    String msg = (cancelled ? "Cancelled. " : "Reverted. ")
                            + "Processed " + totalProcessed + ", cleared " + touched
                            + (skipped > 0 ? ", skipped " + skipped : "");
                    lblStampStatus.setText(msg);
                    btnStampHistory.setEnabled(true);
                    btnCancelStamp.setEnabled(false);
                    api.logging().logToOutput("[burp-dedupe] " + msg);
                });
            }
        });
    }

    public void startHistoryStamp() {
        if (stampThread != null && stampThread.isAlive()) return;
        // Reset the seen-set so historical pass produces consistent verdicts.
        engine.reset();
        stampCancel.set(false);
        btnStampHistory.setEnabled(false);
        btnCancelStamp.setEnabled(true);
        lblStampStatus.setText("Starting…");
        api.logging().logToOutput("[burp-dedupe] stamping existing proxy history");

        stampThread = stamper.runAsync(stampCancel, new HistoryStamper.Progress() {
            @Override
            public void onProgress(int done, int total, DedupeEngine.Result lastResult) {
                SwingUtilities.invokeLater(() ->
                        lblStampStatus.setText("Stamping " + done + " / " + total + "…"));
            }
            @Override
            public void onFinished(int totalProcessed, int stamped, int skipped, boolean cancelled) {
                SwingUtilities.invokeLater(() -> {
                    String msg = (cancelled ? "Cancelled. " : "Done. ")
                            + "Processed " + totalProcessed + ", stamped " + stamped
                            + (skipped > 0 ? ", skipped " + skipped : "");
                    lblStampStatus.setText(msg);
                    btnStampHistory.setEnabled(true);
                    btnCancelStamp.setEnabled(false);
                    api.logging().logToOutput("[burp-dedupe] " + msg);
                    refreshStats();
                });
            }
        });
    }

    private JPanel buildOverridesPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(titled("Header overrides (used by right-click → Dedupe → Send unique to Organizer)"));

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(rbReplaceOrAdd);
        modeGroup.add(rbReplaceOnly);

        taOverrideHeaders.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        taOverrideHeaders.setLineWrap(false);
        taOverrideHeaders.setToolTipText("One header per line, e.g. 'Cookie: a=1; b=2'. Blank lines and # comments ignored.");
        JScrollPane taScroll = new JScrollPane(taOverrideHeaders);

        JPanel modePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        modePanel.add(rbReplaceOrAdd);
        modePanel.add(rbReplaceOnly);

        lblOverrideStatus.setFont(lblOverrideStatus.getFont().deriveFont(Font.ITALIC));

        GridBagConstraints g = gbc();
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        panel.add(cbOverrideEnabled, g);
        g.gridy++; panel.add(new JLabel("Headers (one per line, 'Name: value'):"), g);
        g.gridy++; g.fill = GridBagConstraints.BOTH; g.weighty = 1.0;
        panel.add(taScroll, g);
        g.gridy++; g.fill = GridBagConstraints.HORIZONTAL; g.weighty = 0;
        panel.add(modePanel, g);
        g.gridy++; panel.add(lblOverrideStatus, g);

        // Auto-apply on any change — no button needed since overrides only take effect
        // when the user actually invokes "Send unique to Organizer" anyway.
        cbOverrideEnabled.addActionListener(e -> applyOverrides());
        rbReplaceOrAdd.addActionListener(e -> applyOverrides());
        rbReplaceOnly.addActionListener(e -> applyOverrides());
        taOverrideHeaders.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e)  { applyOverrides(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e)  { applyOverrides(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyOverrides(); }
        });
        return panel;
    }

    private void applyOverrides() {
        List<String> errors = new ArrayList<>();
        HeaderOverrideSet.Mode mode = rbReplaceOnly.isSelected()
                ? HeaderOverrideSet.Mode.REPLACE_ONLY
                : HeaderOverrideSet.Mode.REPLACE_OR_ADD;
        HeaderOverrideSet next = HeaderOverrideSet.parse(
                taOverrideHeaders.getText(),
                mode,
                false, // inScopeOnly no longer meaningful — all selected items are sent
                cbOverrideEnabled.isSelected(),
                errors);
        overridesRef.set(next);

        String status;
        if (!cbOverrideEnabled.isSelected()) {
            status = "Disabled — tick checkbox to enable";
        } else if (next.size() == 0) {
            status = "Enabled — paste headers above to apply on next 'Send unique to Organizer'";
        } else {
            status = "Enabled — " + next.size() + " header(s) ready";
        }
        if (!errors.isEmpty()) {
            status += " (" + errors.size() + " warning(s), see logs)";
            for (String err : errors) api.logging().logToOutput("[burp-dedupe] override: " + err);
        }
        lblOverrideStatus.setText(status);
        // Don't log on every keystroke — only when count or enabled flag actually changes.
        boolean enabledNow = cbOverrideEnabled.isSelected();
        int countNow = next.size();
        if (enabledNow != lastLoggedEnabled || countNow != lastLoggedCount) {
            api.logging().logToOutput("[burp-dedupe] header overrides updated: "
                    + countNow + " header(s), enabled=" + enabledNow);
            lastLoggedEnabled = enabledNow;
            lastLoggedCount = countNow;
        }
    }

    private boolean lastLoggedEnabled = false;
    private int lastLoggedCount = -1;
}
