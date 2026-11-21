package ollamaat.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import ollamaat.Engine;
import ollamaat.Settings;
import ollamaat.agent.Agent;
import ollamaat.agent.Approvals;
import ollamaat.agent.AuditLog;
import ollamaat.agent.Memory;
import ollamaat.agent.Policy;
import ollamaat.agent.SkillLibrary;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.*;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.time.Instant;
import java.util.*;
import java.util.List;

/** The AuditLens suite tab. */
@SuppressWarnings("serial")
public final class MainPanel extends JPanel {
    private final Engine engine;
    private final JTextArea task = new JTextArea(4, 60);
    private final JTextPane transcript = new JTextPane();
    private final JButton run = new JButton("Run agent"), stop = new JButton("Stop");
    private final JCheckBox readOnly = new JCheckBox("Read-only analysis (no requests)");
    private final JComboBox<Settings.Autonomy> autonomy = new JComboBox<>(Settings.Autonomy.values());
    private final JLabel status = new JLabel("Idle"), ctxLabel = new JLabel("Context: none");
    private final DefaultListModel<Approvals.Request> pendingModel = new DefaultListModel<>();
    private final JList<Approvals.Request> pendingList = new JList<>(pendingModel);
    private final JTextArea approvalDetail = new JTextArea();
    private final Set<String> selectedSkills = new LinkedHashSet<>();
    private final StringBuilder contextText = new StringBuilder();
    private int contextCount;
    private final ActiveScanPanel activeScanPanel;
    private final JTabbedPane tabs = new JTabbedPane();
    // Shared by the Findings tab and the Burp "Send to AuditLens" menu, so both report progress in one place.
    private final JLabel findingsStatus = new JLabel(" ");
    private final java.util.concurrent.atomic.AtomicBoolean reviewActive = new java.util.concurrent.atomic.AtomicBoolean(false);

    public MainPanel(Engine engine) {
        super(new BorderLayout());
        this.engine = engine;
        this.activeScanPanel = new ActiveScanPanel(engine);
        tabs.addTab("Agent", agentTab());
        tabs.addTab("Active Scan", activeScanPanel);
        tabs.addTab("Findings", findingsTab());
        tabs.addTab("Audit log", auditTab());
        tabs.addTab("Notes", notesTab());
        tabs.addTab("Settings", new SettingsPanel(engine));
        add(tabs, BorderLayout.CENTER);
        engine.approvals.onChange(() -> SwingUtilities.invokeLater(this::refreshApprovals));
        autonomy.setSelectedItem(engine.settings.autonomy());
        autonomy.addActionListener(e -> engine.settings.autonomy((Settings.Autonomy) autonomy.getSelectedItem()));
        engine.api.userInterface().applyThemeToComponent(this);
    }

    // ------------------------------------------------------------------ agent tab
    private JComponent agentTab() {
        JPanel top = new JPanel(new BorderLayout(4, 4));
        task.setLineWrap(true);
        task.setWrapStyleWord(true);
        task.setText("Review the captured in-scope traffic for access-control weaknesses and report anything you can verify.");
        top.add(new JScrollPane(task), BorderLayout.CENTER);

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton skillsBtn = new JButton("Skills…");
        skillsBtn.addActionListener(e -> pickSkills());
        JButton clearCtx = new JButton("Clear context");
        clearCtx.addActionListener(e -> { contextText.setLength(0); contextCount = 0; ctxLabel.setText("Context: none"); });
        controls.add(run); controls.add(stop); controls.add(new JLabel("Autonomy:")); controls.add(autonomy);
        controls.add(readOnly); controls.add(skillsBtn); controls.add(ctxLabel); controls.add(clearCtx);
        stop.setEnabled(false);
        run.addActionListener(e -> startRun(task.getText(), readOnly.isSelected()));
        stop.addActionListener(e -> engine.stop());
        top.add(controls, BorderLayout.SOUTH);

        transcript.setEditable(false);
        transcript.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JPanel right = new JPanel(new BorderLayout(4, 4));
        right.setBorder(BorderFactory.createTitledBorder("Pending approvals"));
        pendingList.setVisibleRowCount(5);
        pendingList.addListSelectionListener(e -> showApproval());
        approvalDetail.setEditable(false);
        approvalDetail.setLineWrap(true);
        approvalDetail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JPanel buttons = new JPanel(new GridLayout(2, 2, 4, 4));
        buttons.add(answerButton("Allow once", Approvals.Answer.ALLOW_ONCE));
        buttons.add(answerButton("Allow for this run", Approvals.Answer.ALLOW_RUN));
        buttons.add(answerButton("Deny", Approvals.Answer.DENY));
        buttons.add(answerButton("Deny & stop run", Approvals.Answer.DENY_STOP));
        right.add(new JScrollPane(pendingList), BorderLayout.NORTH);
        right.add(new JScrollPane(approvalDetail), BorderLayout.CENTER);
        right.add(buttons, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(transcript), right);
        split.setResizeWeight(0.68);

        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        p.add(top, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        p.add(status, BorderLayout.SOUTH);
        return p;
    }

    private JButton answerButton(String label, Approvals.Answer a) {
        JButton b = new JButton(label);
        b.addActionListener(e -> {
            Approvals.Request r = pendingList.getSelectedValue();
            if (r != null) engine.approvals.answer(r, a);
        });
        return b;
    }

    private void refreshApprovals() {
        Approvals.Request sel = pendingList.getSelectedValue();
        pendingModel.clear();
        List<Approvals.Request> l = engine.approvals.pending();
        for (Approvals.Request r : l) pendingModel.addElement(r);
        if (!l.isEmpty()) {
            pendingList.setSelectedIndex(0);
            if (sel == null) { Toolkit.getDefaultToolkit().beep(); engine.api.logging().raiseInfoEvent("AuditLens: approval needed (AuditLens tab)"); }
        }
        showApproval();
    }

    private void showApproval() {
        Approvals.Request r = pendingList.getSelectedValue();
        approvalDetail.setText(r == null ? "No pending approvals." : "WHY ASKED: " + r.reason + "\nTOOL: " + r.tool + "\n\n" + r.detail);
        approvalDetail.setCaretPosition(0);
    }

    private void pickSkills() {
        JPanel p = new JPanel(new GridLayout(0, 1));
        Map<String, JCheckBox> boxes = new LinkedHashMap<>();
        for (SkillLibrary.Skill s : engine.skills().all()) {
            JCheckBox cb = new JCheckBox(s.name() + " - " + s.description(), selectedSkills.contains(s.name()));
            boxes.put(s.name(), cb);
            p.add(cb);
        }
        if (JOptionPane.showConfirmDialog(this, new JScrollPane(p), "Preload skills into the run (the agent can also load others itself)",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION) {
            selectedSkills.clear();
            boxes.forEach((n, cb) -> { if (cb.isSelected()) selectedSkills.add(n); });
        }
    }

    // ------------------------------------------------------------------ run control (also used by the context menu)
    /** Called from the right-click context menu to jump to the Active Scan tab with these items preloaded. */
    public void scanFromContextMenu(List<HttpRequestResponse> items) {
        activeScanPanel.preload(items);
        tabs.setSelectedComponent(activeScanPanel);
    }

    public void addContext(List<HttpRequestResponse> items) {
        String d = engine.describe(items);
        synchronized (contextText) { contextText.append(d); contextCount += items.size(); }
        SwingUtilities.invokeLater(() -> ctxLabel.setText("Context: " + contextCount + " item(s)"));
    }

    public void startRun(String taskText, boolean readOnlyRun) {
        if (taskText == null || taskText.isBlank()) { JOptionPane.showMessageDialog(this, "Enter a task first."); return; }
        if (engine.settings.model().isBlank()) { JOptionPane.showMessageDialog(this, "Choose an Ollama model in the Settings tab first."); return; }
        transcript.setText("");
        String ctx;
        synchronized (contextText) { ctx = contextText.toString(); }
        boolean ok = engine.start(taskText, new ArrayList<>(selectedSkills), ctx, !readOnlyRun, this::onEvent, () -> SwingUtilities.invokeLater(() -> {
            run.setEnabled(true); stop.setEnabled(false); status.setText("Idle");
        }));
        if (!ok) { engine.api.logging().raiseInfoEvent("AuditLens: a run is already in progress"); return; }
        run.setEnabled(false); stop.setEnabled(true); status.setText("Running…");
    }

    private void onEvent(Agent.EventType t, String text) {
        SwingUtilities.invokeLater(() -> {
            Color c; String tag;
            switch (t) {
                case USER: c = new Color(0x4e9a06); tag = "TASK"; break;
                case ASSISTANT: c = new Color(0x3465a4); tag = "MODEL"; break;
                case TOOL_CALL: c = new Color(0xc4a000); tag = "TOOL "; break;
                case TOOL_RESULT: c = Color.GRAY; tag = "  ←  "; break;
                case POLICY: c = new Color(0xf57900); tag = "POLICY"; break;
                case ERROR: c = new Color(0xcc0000); tag = "ERROR"; break;
                case DONE: c = new Color(0x75507b); tag = "DONE"; break;
                default: c = Color.GRAY; tag = "SYS  ";
            }
            append("[" + tag + "] ", c, true);
            append(text + "\n", null, false);
            if (t == Agent.EventType.TOOL_CALL) status.setText("Running: " + text.split(" ")[0]);
        });
    }

    private void append(String s, Color c, boolean bold) {
        StyledDocument d = transcript.getStyledDocument();
        SimpleAttributeSet a = new SimpleAttributeSet();
        if (c != null) StyleConstants.setForeground(a, c);
        StyleConstants.setBold(a, bold);
        try { d.insertString(d.getLength(), s, a); } catch (BadLocationException ignored) { }
        transcript.setCaretPosition(d.getLength());
    }

    // ------------------------------------------------------------------ findings
    private JComponent findingsTab() {
        AbstractTableModel m = new AbstractTableModel() {
            final String[] cols = {"Time", "Severity", "Confidence", "Title", "URL", "AI Triage (FP)", "Mark false positive", "Evidence", "In Burp issues"};
            public int getRowCount() { return engine.memory.findings().size(); }
            public int getColumnCount() { return cols.length; }
            public String getColumnName(int c) { return cols[c]; }
            public Object getValueAt(int r, int c) {
                Memory.Finding f = engine.memory.findings().get(r);
                switch (c) {
                    case 0: return Instant.ofEpochMilli(f.time()).toString();
                    case 1: return f.severity();
                    case 2: return f.confidence();
                    case 3: return f.title();
                    case 4: return f.url();
                    case 5: return f.aiTriage();
                    case 6: return f.falsePositive();
                    case 7: return String.join(", ", f.evidence());
                    default: return f.reportedToBurp() ? "yes" : "no";
                }
            }
            /** Column 6 is a checkbox per row: ticking it marks the finding as a false positive. */
            @Override public Class<?> getColumnClass(int c) { return c == 6 ? Boolean.class : String.class; }
            @Override public boolean isCellEditable(int r, int c) { return c == 6; }
            @Override public void setValueAt(Object v, int r, int c) {
                if (c != 6 || r < 0 || r >= engine.memory.findings().size()) return;
                boolean fp = Boolean.TRUE.equals(v);
                engine.memory.setFalsePositive(engine.memory.findings().get(r), fp);
                findingsStatus.setText(fp ? "Marked as false positive. It is left out of generated reports."
                        : "Restored. It is included in generated reports again.");
            }
        };
        engine.memory.onChange(() -> SwingUtilities.invokeLater(m::fireTableDataChanged));
        JTable table = new JTable(m);
        table.setAutoCreateRowSorter(true);
        JTextArea detail = new JTextArea();
        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        // The false-positive checkbox belongs to the selected finding. The table reloads after each change and clears
        // the selection, so the handler reselects that row afterwards.
        final Memory.Finding[] shown = {null};
        final int[] shownRow = {-1};
        JCheckBox fpBox = new JCheckBox("Mark as false positive (leave out of the final report)");
        fpBox.setEnabled(false);
        table.getSelectionModel().addListSelectionListener(e -> {
            int r = table.getSelectedRow();
            if (r < 0) {
                shown[0] = null; shownRow[0] = -1;
                fpBox.setEnabled(false); fpBox.setSelected(false);
                return;
            }
            Memory.Finding f = engine.memory.findings().get(table.convertRowIndexToModel(r));
            shown[0] = f; shownRow[0] = table.convertRowIndexToModel(r);
            fpBox.setEnabled(true); fpBox.setSelected(f.falsePositive());
            detail.setText(f.title() + "\n\nSeverity: " + f.severity() + "   Confidence: " + f.confidence() + "\nURL: " + f.url()
                    + "\n\n" + f.detail() + (f.remediation().isEmpty() ? "" : "\n\nRemediation:\n" + f.remediation()));
            detail.setCaretPosition(0);
        });
        fpBox.addActionListener(e -> {
            Memory.Finding f = shown[0];
            if (f == null) return;
            boolean fp = fpBox.isSelected();
            engine.memory.setFalsePositive(f, fp);
            findingsStatus.setText(fp ? "Marked as false positive. It is left out of generated reports."
                    : "Restored. It is included in generated reports again.");
            int modelRow = shownRow[0];
            SwingUtilities.invokeLater(() -> {
                int view = table.convertRowIndexToView(modelRow);
                if (view >= 0) table.setRowSelectionInterval(view, view);
            });
        });
        JPanel detailPanel = new JPanel(new BorderLayout());
        detailPanel.add(new JScrollPane(detail), BorderLayout.CENTER);
        detailPanel.add(fpBox, BorderLayout.SOUTH);
        JSplitPane sp = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), detailPanel);
        sp.setResizeWeight(0.5);

        // Right-click a row (or several) to send its captured request to Burp Repeater, or re-check it with the AI.
        JPopupMenu rowMenu = new JPopupMenu();
        JMenuItem toRepeaterItem = new JMenuItem("Send to Repeater (manual analysis)");
        JMenuItem reCheckItem = new JMenuItem("Re-check selected with AI (false-positive analysis)");
        rowMenu.add(toRepeaterItem);
        rowMenu.add(reCheckItem);
        toRepeaterItem.addActionListener(e -> sendSelectedToRepeater(table));
        reCheckItem.addActionListener(e -> reCheckSelected(table));
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mousePressed(java.awt.event.MouseEvent e) { maybePopup(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { maybePopup(e); }
            private void maybePopup(java.awt.event.MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = table.rowAtPoint(e.getPoint());
                if (row >= 0 && !table.isRowSelected(row)) table.setRowSelectionInterval(row, row);
                if (table.getSelectedRowCount() > 0) rowMenu.show(table, e.getX(), e.getY());
            }
        });

        JButton report = new JButton("Generate report (HTML / Excel)…");
        report.addActionListener(e -> ReportDialog.showAndSave(this, engine));
        JButton sync = new JButton("Sync [AI] issues from Burp");
        Runnable doSync = () -> new Thread(() -> {
            int n = engine.syncFindingsFromBurp();
            String st = engine.memory.findings().size() + " finding(s)" + (n > 0 ? " (+" + n + " imported from Burp issues)" : "")
                    + ".  " + engine.passiveStatus();
            // Don't overwrite the live progress/result line while an AI review is running; just refresh the table.
            SwingUtilities.invokeLater(() -> { if (!reviewActive.get()) findingsStatus.setText(st); m.fireTableDataChanged(); });
        }, "AuditLens-findings-sync").start();
        sync.addActionListener(e -> doSync.run());

        JButton importBurp = new JButton("Import Burp issues");
        importBurp.setToolTipText("Import all of Burp's own scanner issues (and other extensions') into this Findings tab and the reports.");
        importBurp.addActionListener(e -> {
            importBurp.setEnabled(false);
            findingsStatus.setText("Importing Burp issues…");
            new Thread(() -> {
                int n = engine.importBurpIssues(false);
                SwingUtilities.invokeLater(() -> {
                    importBurp.setEnabled(true);
                    if (!reviewActive.get())
                        findingsStatus.setText(engine.memory.findings().size() + " finding(s) total. Imported " + n + " new from Burp.");
                    m.fireTableDataChanged();
                });
            }, "AuditLens-import-burp").start();
        });

        JButton fpAnalyze = new JButton("AI false-positive analysis");
        fpAnalyze.setToolTipText("Use the local model to judge each finding (esp. imported Burp issues) as true positive / false positive / needs review.");
        fpAnalyze.addActionListener(e -> {
            Object[] opts = {"All findings", "Only Burp issues", "Cancel"};
            int ch = JOptionPane.showOptionDialog(this, "Run AI false-positive analysis on which findings?\n"
                    + "(Uses your local model on already-captured evidence; sends no new requests.)",
                    "AI false-positive analysis", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, opts, opts[1]);
            if (ch != 0 && ch != 1) return;
            boolean burpOnly = ch == 1;
            fpAnalyze.setEnabled(false);
            reviewActive.set(true);
            findingsStatus.setText("AI false-positive analysis starting…");
            boolean ok = engine.startFalsePositiveAnalysis(burpOnly, true, new Engine.ReviewListener() {
                int seen = 0, fps = 0;
                public void event(String tag, String text) {
                    if (tag.equals("REVIEW")) seen++;
                    if (tag.equals("FOUND")) fps++;
                    final int s2 = seen, f2 = fps;
                    SwingUtilities.invokeLater(() -> {
                        switch (tag) {
                            case "START" -> findingsStatus.setText("AI triage: " + text);
                            case "REVIEW" -> findingsStatus.setText("AI triage: analyzing " + s2 + " … (" + f2 + " false positive(s) so far)");
                            case "DONE" -> findingsStatus.setText("AI triage: " + text);
                            case "ERROR" -> findingsStatus.setText("AI triage error: " + text);
                            default -> {}
                        }
                        m.fireTableDataChanged();
                    });
                }
                public void done(int analyzed, int fp) {
                    reviewActive.set(false);
                    SwingUtilities.invokeLater(() -> { fpAnalyze.setEnabled(true); m.fireTableDataChanged(); });
                }
            }, null);
            if (!ok) { reviewActive.set(false); fpAnalyze.setEnabled(true); findingsStatus.setText("Busy: an agent run, scan or review is already in progress."); }
        });

        JButton aiReview = new JButton("Review proxy history (AI)");
        aiReview.addActionListener(e -> {
            String in = JOptionPane.showInputDialog(this, "How many distinct in-scope exchanges should the model review?\n"
                    + "(Reads already-captured proxy traffic; sends no new requests.)", "25");
            if (in == null) return;
            int max;
            try { max = Math.max(1, Integer.parseInt(in.trim())); } catch (NumberFormatException ex) { max = 25; }
            aiReview.setEnabled(false);
            reviewActive.set(true);
            findingsStatus.setText("AI review starting…");
            boolean ok = engine.startProxyReview(max, true, new Engine.ReviewListener() {
                int seen = 0, hits = 0;
                public void event(String tag, String text) {
                    if (tag.equals("FOUND")) hits++;
                    if (tag.equals("REVIEW")) seen++;
                    final int s2 = seen, h2 = hits;
                    SwingUtilities.invokeLater(() -> {
                        switch (tag) {
                            case "START" -> findingsStatus.setText("AI review: " + text);
                            case "REVIEW" -> findingsStatus.setText("AI review: reviewing " + s2 + " … (" + h2 + " finding(s) so far)");
                            case "FOUND" -> findingsStatus.setText("AI review: " + text);
                            case "ERROR" -> findingsStatus.setText("AI review error: " + text);
                            default -> {}
                        }
                        m.fireTableDataChanged();
                    });
                }
                public void done(int reviewed, int findings) {
                    reviewActive.set(false);
                    SwingUtilities.invokeLater(() -> { aiReview.setEnabled(true); m.fireTableDataChanged();
                        findingsStatus.setText(engine.memory.findings().size() + " finding(s) total.  Last AI review: "
                            + reviewed + " reviewed, " + findings + " new. " + (findings == 0 ? "(Nothing flagged on these responses.)" : "")); });
                }
            }, null);
            if (!ok) { reviewActive.set(false); aiReview.setEnabled(true); findingsStatus.setText("Busy: an agent run, scan or review is already in progress."); }
        });

        // Manual analysis section: hand the selected findings' requests to Burp Repeater to validate them yourself.
        JPanel manual = new JPanel(new FlowLayout(FlowLayout.LEFT));
        manual.setBorder(BorderFactory.createTitledBorder("Manual analysis"));
        JButton toRepeaterBtn = new JButton("Send selected to Repeater");
        toRepeaterBtn.setToolTipText("Opens each selected finding's captured request in Burp Repeater, named after the finding. Nothing is sent until you press Send there.");
        toRepeaterBtn.addActionListener(e -> sendSelectedToRepeater(table));
        manual.add(toRepeaterBtn);
        manual.add(new JLabel("Select rows (Ctrl/Shift for several), then validate in Repeater. Right-click a row for the same action."));

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottom.add(report);
        bottom.add(sync);
        bottom.add(importBurp);
        bottom.add(fpAnalyze);
        // Visible per-selection action: triage only the selected rows (same as the right-click item).
        JButton triageSelected = new JButton("Triage selected (AI)");
        triageSelected.setToolTipText("Run the AI false-positive check on the rows you selected only. Re-judges rows that already have a verdict.");
        triageSelected.addActionListener(e -> reCheckSelected(table));
        bottom.add(triageSelected);
        bottom.add(aiReview);
        bottom.add(findingsStatus);
        // Sync shortly after load (Burp's issue list is ready by then) and every 20s so passive issues show up on their own.
        javax.swing.Timer timer = new javax.swing.Timer(20_000, e -> doSync.run());
        timer.setInitialDelay(3_000);
        timer.start();
        engine.onUnload(timer::stop);

        JPanel p = new JPanel(new BorderLayout());
        p.add(sp, BorderLayout.CENTER);
        JPanel south = new JPanel(new BorderLayout());
        south.add(manual, BorderLayout.NORTH);
        south.add(bottom, BorderLayout.SOUTH);
        p.add(south, BorderLayout.SOUTH);
        return p;
    }

    // ------------------------------------------------------------------ manual analysis and Burp issue hand-off
    private java.util.List<Memory.Finding> selectedFindings(JTable table) {
        java.util.List<Memory.Finding> out = new ArrayList<>();
        for (int r : table.getSelectedRows()) {
            int m = table.convertRowIndexToModel(r);
            if (m >= 0 && m < engine.memory.findings().size()) out.add(engine.memory.findings().get(m));
        }
        return out;
    }

    private void sendSelectedToRepeater(JTable table) {
        java.util.List<Memory.Finding> sel = selectedFindings(table);
        if (sel.isEmpty()) { findingsStatus.setText("Select one or more findings first."); return; }
        findingsStatus.setText("Sending " + sel.size() + " finding(s) to Burp Repeater…");
        new Thread(() -> {
            int n = engine.sendToRepeater(sel);
            SwingUtilities.invokeLater(() -> findingsStatus.setText(n == 0
                    ? "Nothing sent: the selected findings have no captured request or URL."
                    : "Sent " + n + " finding(s) to Burp Repeater. Validate there and note the outcome."));
        }, "AuditLens-repeater").start();
    }

    private void reCheckSelected(JTable table) {
        java.util.List<Memory.Finding> sel = selectedFindings(table);
        if (sel.isEmpty()) { findingsStatus.setText("Select one or more findings first."); return; }
        reviewActive.set(true);
        findingsStatus.setText("AI false-positive check starting…");
        if (!engine.triageFindings(sel, triageListener(), null)) {
            reviewActive.set(false);
            findingsStatus.setText("Busy: an agent run, scan or review is already in progress, or no model is selected.");
        }
    }

    /** Repeater "Analyze with AuditLens" button: read-only agent review of one request (and its response, if captured). */
    public void analyzeRequest(HttpRequestResponse rr) {
        addContext(List.of(rr));
        startRun("Analyze this request for security weaknesses visible in it (use the refs in the context). Explain what it does, "
                + "flag risky parameters, tokens, headers and data exposure, and propose concrete manual tests. Do not send requests.", true);
        SwingUtilities.invokeLater(() -> tabs.setSelectedIndex(tabs.indexOfTab("Agent")));
    }

    /** Burp issue menu "Investigate with AuditLens agent": one issue, its captured messages as context. */
    public void investigateIssue(burp.api.montoya.scanner.audit.issues.AuditIssue issue) {
        addContext(new ArrayList<>(issue.requestResponses()));
        startRun("Investigate the Burp issue \"" + issue.name() + "\" at " + issue.baseUrl() + ". Use the captured refs in the context. "
                + "Say whether the evidence shows a real issue, its impact, and the minimal manual tests that would confirm it. Do not send requests.", true);
        SwingUtilities.invokeLater(() -> tabs.setSelectedIndex(tabs.indexOfTab("Agent")));
    }

    /** Burp "Send to AuditLens" on selected issues: imports them as findings and runs the AI analysis on them. */
    public void analyzeBurpIssues(java.util.List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues) {
        SwingUtilities.invokeLater(() -> tabs.setSelectedIndex(tabs.indexOfTab("Findings")));
        reviewActive.set(true);
        findingsStatus.setText("Sent " + issues.size() + " Burp issue(s) to AuditLens for AI analysis…");
        if (!engine.analyzeIssues(issues, triageListener(), null)) {
            reviewActive.set(false);
            findingsStatus.setText("Busy: an agent run, scan or review is already in progress, or no model is selected.");
        }
    }

    private Engine.ReviewListener triageListener() {
        return new Engine.ReviewListener() {
            int seen = 0, fps = 0;
            public void event(String tag, String text) {
                if (tag.equals("REVIEW")) seen++;
                if (tag.equals("FOUND")) fps++;
                final int s2 = seen, f2 = fps;
                SwingUtilities.invokeLater(() -> {
                    switch (tag) {
                        case "START" -> findingsStatus.setText("AI triage: " + text);
                        case "REVIEW" -> findingsStatus.setText("AI triage: analyzing " + s2 + " … (" + f2 + " false positive(s) so far)");
                        case "DONE" -> findingsStatus.setText("AI triage: " + text);
                        case "ERROR" -> findingsStatus.setText("AI triage error: " + text);
                        default -> { }
                    }
                });
            }
            public void done(int analyzed, int fp) { reviewActive.set(false); }
        };
    }

    // ------------------------------------------------------------------ audit log
    private JComponent auditTab() {
        AbstractTableModel m = new AbstractTableModel() {
            final String[] cols = {"Time", "Run", "Tool", "Action", "Verdict", "Decided by", "Outcome"};
            public int getRowCount() { return engine.audit.all().size(); }
            public int getColumnCount() { return cols.length; }
            public String getColumnName(int c) { return cols[c]; }
            public Object getValueAt(int r, int c) {
                AuditLog.Entry e = engine.audit.all().get(r);
                switch (c) {
                    case 0: return Instant.ofEpochMilli(e.time()).toString();
                    case 1: return e.run();
                    case 2: return e.tool();
                    case 3: return e.summary();
                    case 4: return e.verdict();
                    case 5: return e.by();
                    default: return e.outcome();
                }
            }
        };
        engine.audit.onChange(() -> SwingUtilities.invokeLater(m::fireTableDataChanged));
        JTable table = new JTable(m);
        table.setAutoCreateRowSorter(true);
        JButton export = new JButton("Export as Markdown…");
        export.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new java.io.File("ollamaat-audit.md"));
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                try { Files.writeString(fc.getSelectedFile().toPath(), engine.audit.toMarkdown()); }
                catch (IOException ex) { JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage()); }
            }
        });
        JPanel p = new JPanel(new BorderLayout());
        p.add(new JScrollPane(table), BorderLayout.CENTER);
        JPanel b = new JPanel(new FlowLayout(FlowLayout.LEFT));
        b.add(export);
        b.add(new JLabel("Every tool call, policy verdict and approval decision is stored in the Burp project."));
        p.add(b, BorderLayout.SOUTH);
        return p;
    }

    // ------------------------------------------------------------------ notes
    private JComponent notesTab() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        Runnable refresh = () -> {
            StringBuilder sb = new StringBuilder();
            for (Memory.Note n : engine.memory.notes())
                sb.append("## ").append(n.title()).append("  (run ").append(n.run()).append(", ").append(Instant.ofEpochMilli(n.time())).append(")\n").append(n.text()).append("\n\n");
            area.setText(sb.length() == 0 ? "No notes yet. The agent saves durable facts here with note_add; they are included in later runs." : sb.toString());
        };
        refresh.run();
        engine.memory.onChange(() -> SwingUtilities.invokeLater(refresh));
        return new JScrollPane(area);
    }
}
