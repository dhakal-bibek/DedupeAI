package burpdedupe.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A standalone window that lists <em>only the unique</em> requests from a selection,
 * styled to mirror Burp's HTTP-history table (same kind of columns, a Notes column
 * carrying our {@code [DEDUPE] …} verdict + {@code [attacker]/[victim] port N} tag, and
 * rows tinted by their Burp highlight colour). Read-only request/response viewers sit
 * beneath the table.
 *
 * <p>The toolbar has a <b>Send to Repeater</b> action and a <b>filter</b> box that
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
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTable table;
    private final TableRowSorter<UniqueTableModel> sorter;
    private final JTextField filterField = new JTextField(26);
    private final JCheckBox regexBox = new JCheckBox("regex");
    private final JLabel status = new JLabel(" ");

    UniqueRequestsViewer(MontoyaApi api, List<HttpRequestResponse> uniques) {
        this.api = api;
        this.uniques = new ArrayList<>(uniques);
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        UniqueTableModel model = new UniqueTableModel(this.uniques);
        this.table = new JTable(model);
        this.sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);   // fixed widths + horizontal scroll, like Burp
        table.setDefaultRenderer(Object.class, new HighlightRenderer(model));
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) return;
            showRow(table.convertRowIndexToModel(viewRow));
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

        JFrame frame = new JFrame("Dedupe — Unique requests (" + this.uniques.size() + ")");
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
        repeater.setToolTipText("Send the selected request to a new Repeater tab.");
        repeater.addActionListener(e -> sendSelectedToRepeater());

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
        status.setText("Showing " + table.getRowCount() + " of " + uniques.size() + " unique request(s).");
    }

    private void showRow(int modelRow) {
        if (modelRow < 0 || modelRow >= uniques.size()) return;
        HttpRequestResponse rr = uniques.get(modelRow);
        requestEditor.setRequest(rr.request());
        responseEditor.setResponse(
                rr.hasResponse() && rr.response() != null ? rr.response() : HttpResponse.httpResponse());
    }

    /** Sends the selected request to a new Repeater tab. */
    private void sendSelectedToRepeater() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) { status.setText("Select a request first."); return; }
        HttpRequestResponse rr = uniques.get(table.convertRowIndexToModel(viewRow));
        HttpRequest req = rr.request();
        if (req == null) { status.setText("Selected row has no request."); return; }

        String label = safe(req::method) + " " + safe(req::url);
        try {
            api.repeater().sendToRepeater(req, "dedupe");
            status.setText("Sent to a new Repeater tab: " + label);
        } catch (RuntimeException ex) {
            api.logging().logToError("[burp-dedupe] send-to-Repeater failed: " + ex);
            status.setText("Send failed: " + ex.getMessage());
        }
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
