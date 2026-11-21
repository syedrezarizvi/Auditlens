package ollamaat.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import ollamaat.Engine;
import ollamaat.scan.ActiveScanEngine;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;
import ollamaat.util.Text;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.*;
import java.awt.*;
import java.util.List;
import java.util.*;
import java.util.function.Predicate;

/** Deterministic, policy-gated active scan: pick endpoints, pick checks, confirm the estimated request count, go.
 *  Every probe still passes through the same scope/approval/budget/block-list rules as the chat agent. */
@SuppressWarnings("serial")
public final class ActiveScanPanel extends JPanel {
    private final Engine engine;
    private final List<HttpRequestResponse> endpoints = new ArrayList<>();
    private EndpointModel model = new EndpointModel();
    private final JTable table = new JTable(model);
    private final JTextField hostFilter = new JTextField(16);
    private final JCheckBox includeStatic = new JCheckBox("Include static assets");
    private final JSpinner maxEndpoints = new JSpinner(new SpinnerNumberModel(200, 1, 2000, 10));
    private final Map<String, JCheckBox> checkBoxes = new LinkedHashMap<>();
    private final JCheckBox passiveOnly = new JCheckBox("Passive only (no requests sent)");
    private final JLabel estimate = new JLabel("Select endpoints and checks to see an estimate.");
    private final JButton start = new JButton("Start scan"), stop = new JButton("Stop");
    private final JTextPane log = new JTextPane();
    private final JLabel status = new JLabel("Idle");

    public ActiveScanPanel(Engine engine) {
        super(new BorderLayout(6, 6));
        this.engine = engine;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton load = new JButton("Load in-scope endpoints from Proxy history");
        load.addActionListener(e -> loadEndpoints());
        JButton selAll = new JButton("Select all"), selNone = new JButton("Select none");
        selAll.addActionListener(e -> setAll(true));
        selNone.addActionListener(e -> setAll(false));
        top.add(load); top.add(new JLabel("Host contains:")); top.add(hostFilter); top.add(includeStatic);
        top.add(new JLabel("Max:")); top.add(maxEndpoints); top.add(selAll); top.add(selNone);

        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(100, 220));

        JPanel checksPanel = new JPanel();
        checksPanel.setLayout(new BoxLayout(checksPanel, BoxLayout.Y_AXIS));
        checksPanel.setBorder(BorderFactory.createTitledBorder("Checks"));
        for (ScanCheck c : engine.scanChecks()) {
            JCheckBox cb = new JCheckBox(c.name() + (c.passiveOnly() ? "  [passive]" : c.perHost() ? "  [once per host]" : ""), true);
            cb.setToolTipText(c.description());
            cb.addActionListener(e -> updateEstimate());
            checkBoxes.put(c.id(), cb);
            checksPanel.add(cb);
        }
        passiveOnly.addActionListener(e -> updateEstimate());
        checksPanel.add(Box.createVerticalStrut(6));
        checksPanel.add(passiveOnly);
        JScrollPane checksScroll = new JScrollPane(checksPanel);
        checksScroll.setPreferredSize(new Dimension(360, 220));

        JPanel middle = new JPanel(new BorderLayout(6, 6));
        middle.add(tableScroll, BorderLayout.CENTER);
        middle.add(checksScroll, BorderLayout.EAST);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        controls.add(start); controls.add(stop);
        JButton report = new JButton("Generate report (HTML / Excel)…");
        report.addActionListener(e -> ReportDialog.showAndSave(this, engine));
        controls.add(report);
        controls.add(estimate);
        stop.setEnabled(false);
        start.addActionListener(e -> startScan());
        stop.addActionListener(e -> engine.stop());

        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JPanel north = new JPanel(new BorderLayout(4, 4));
        north.add(top, BorderLayout.NORTH);
        north.add(middle, BorderLayout.CENTER);
        north.add(controls, BorderLayout.SOUTH);

        add(north, BorderLayout.NORTH);
        add(new JScrollPane(log), BorderLayout.CENTER);
        add(status, BorderLayout.SOUTH);

        table.getModel().addTableModelListener(e -> updateEstimate());
        engine.api.userInterface().applyThemeToComponent(this);
    }

    private void loadEndpoints() {
        String host = hostFilter.getText().trim().toLowerCase();
        boolean statics = includeStatic.isSelected();
        int max = ((Number) maxEndpoints.getValue()).intValue();
        Set<String> seen = new LinkedHashSet<>();
        List<HttpRequestResponse> found = new ArrayList<>();
        for (ProxyHttpRequestResponse p : engine.evidence.proxy()) {
            if (found.size() >= max) break;
            String url = p.finalRequest().url();
            if (!engine.api.scope().isInScope(url)) continue;
            if (!host.isEmpty() && !p.httpService().host().toLowerCase().contains(host)) continue;
            String ext = p.finalRequest().fileExtension().toLowerCase();
            if (!statics && Set.of("js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "map", "webp").contains(ext)) continue;
            String key = p.finalRequest().method() + " " + p.httpService().host() + Text.pathTemplate(p.finalRequest().path());
            if (!seen.add(key)) continue;
            found.add(HttpRequestResponse.httpRequestResponse(p.finalRequest(), p.hasResponse() ? p.response() : null));
        }
        setEndpoints(found);
        status.setText(found.size() + " unique in-scope endpoint(s) loaded.");
    }

    /** Called from the right-click context menu: preload specific messages and jump here. */
    public void preload(List<HttpRequestResponse> items) {
        setEndpoints(new ArrayList<>(items));
        status.setText(items.size() + " item(s) added from selection.");
    }

    private void setEndpoints(List<HttpRequestResponse> items) {
        endpoints.clear();
        endpoints.addAll(items);
        model = new EndpointModel();
        table.setModel(model);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.getModel().addTableModelListener(e -> updateEstimate());
        updateEstimate();
    }

    private void setAll(boolean v) {
        Arrays.fill(model.sel, v);
        model.fireTableDataChanged();
        updateEstimate();
    }

    private List<HttpRequestResponse> selectedEndpoints() {
        List<HttpRequestResponse> out = new ArrayList<>();
        for (int i = 0; i < endpoints.size(); i++) if (model.sel[i]) out.add(endpoints.get(i));
        return out;
    }

    private List<ScanCheck> selectedChecks() {
        List<ScanCheck> out = new ArrayList<>();
        for (ScanCheck c : engine.scanChecks()) if (checkBoxes.get(c.id()).isSelected() && (!passiveOnly.isSelected() || c.passiveOnly())) out.add(c);
        return out;
    }

    private void updateEstimate() {
        List<HttpRequestResponse> sel = selectedEndpoints();
        List<ScanCheck> checks = selectedChecks();
        int est = engine.estimateScanRequests(sel, checks);
        estimate.setText(sel.size() + " endpoint(s), " + checks.size() + " check(s) selected — up to ~" + est + " request(s) "
                + "(bounded by the global rate limit and " + engine.settings.maxRequestsPerRun() + "/run budget in Settings).");
    }

    private void startScan() {
        List<HttpRequestResponse> sel = selectedEndpoints();
        List<ScanCheck> checks = selectedChecks();
        if (sel.isEmpty()) { JOptionPane.showMessageDialog(this, "Load and select at least one endpoint first."); return; }
        if (checks.isEmpty()) { JOptionPane.showMessageDialog(this, "Select at least one check."); return; }
        int est = engine.estimateScanRequests(sel, checks);
        boolean netAllowed = !passiveOnly.isSelected();
        int confirm = JOptionPane.showConfirmDialog(this,
                "This will scan " + sel.size() + " endpoint(s) with " + checks.size() + " check(s), sending up to ~" + est
                        + " request(s)" + (netAllowed ? "" : " (passive checks only; no requests will be sent)")
                        + ".\nEvery request still goes through Burp scope, the request budget/rate limit, and your Autonomy approval "
                        + "settings in the Agent tab.\n\nStart the scan?",
                "Confirm active scan", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.OK_OPTION) return;

        log.setText("");
        boolean ok = engine.startActiveScan(sel, checks, netAllowed, new ActiveScanEngine.Listener() {
            public void event(ActiveScanEngine.EventType t, String s) { onEvent(t, s); }
        }, () -> SwingUtilities.invokeLater(() -> { start.setEnabled(true); stop.setEnabled(false); status.setText("Idle"); }));
        if (!ok) { JOptionPane.showMessageDialog(this, "A scan or agent run is already in progress."); return; }
        start.setEnabled(false); stop.setEnabled(true); status.setText("Scanning…");
    }

    private void onEvent(ActiveScanEngine.EventType t, String text) {
        SwingUtilities.invokeLater(() -> {
            Color c; String tag;
            switch (t) {
                case START: c = new Color(0x4e9a06); tag = "START"; break;
                case ENDPOINT: c = new Color(0x3465a4); tag = "TARGET"; break;
                case CHECK: c = Color.GRAY; tag = "CHECK "; break;
                case FINDING: c = new Color(0xc0392b); tag = "FOUND "; break;
                case SKIP: c = new Color(0xf57900); tag = "SKIP  "; break;
                case ERROR: c = new Color(0xcc0000); tag = "ERROR"; break;
                default: c = new Color(0x75507b); tag = "DONE";
            }
            append("[" + tag + "] ", c, true);
            append(text + "\n", null, false);
            if (t == ActiveScanEngine.EventType.ENDPOINT) status.setText(text);
        });
    }

    private void append(String s, Color c, boolean bold) {
        StyledDocument d = log.getStyledDocument();
        SimpleAttributeSet a = new SimpleAttributeSet();
        if (c != null) StyleConstants.setForeground(a, c);
        StyleConstants.setBold(a, bold);
        try { d.insertString(d.getLength(), s, a); } catch (BadLocationException ignored) { }
        log.setCaretPosition(d.getLength());
    }

    private final class EndpointModel extends AbstractTableModel {
        final boolean[] sel = new boolean[endpoints.size()];
        final String[] cols = {"", "Method", "URL", "Status"};
        { Arrays.fill(sel, true); }
        public int getRowCount() { return endpoints.size(); }
        public int getColumnCount() { return cols.length; }
        public String getColumnName(int c) { return cols[c]; }
        public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        public boolean isCellEditable(int r, int c) { return c == 0; }
        public Object getValueAt(int r, int c) {
            HttpRequestResponse rr = endpoints.get(r);
            return switch (c) {
                case 0 -> sel[r];
                case 1 -> rr.request().method();
                case 2 -> rr.request().url();
                default -> rr.hasResponse() ? String.valueOf(rr.response().statusCode()) : "-";
            };
        }
        public void setValueAt(Object v, int r, int c) { if (c == 0) { sel[r] = (Boolean) v; updateEstimate(); } }
    }
}
