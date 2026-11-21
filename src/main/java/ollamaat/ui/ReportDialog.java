package ollamaat.ui;

import ollamaat.Engine;
import ollamaat.report.HtmlReport;
import ollamaat.report.ReportOptions;
import ollamaat.report.ExcelReport;

import javax.swing.*;
import java.awt.*;
import java.awt.Desktop;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** Shared "generate the HTML report" flow used from both the Findings tab and the Active Scan tab. */
public final class ReportDialog {
    private ReportDialog() {}

    /** AuditLens_&lt;project&gt;_&lt;yyyy-MM-dd&gt;.&lt;ext&gt;. Project falls back to the scope's host, then "Project". */
    public static String defaultFileName(String project, String scope, String ext) {
        String name = project == null ? "" : project.trim();
        if (name.isEmpty() && scope != null && !scope.isBlank()) {
            String s = scope.trim();
            if (!s.contains("://")) s = "http://" + s;
            try { name = java.net.URI.create(s).getHost(); } catch (IllegalArgumentException ignored) { name = ""; }
        }
        if (name == null || name.isBlank()) name = "Project";
        String safe = name.replaceAll("[^A-Za-z0-9.-]+", "-").replaceAll("^-+|-+$", "");
        if (safe.isEmpty()) safe = "Project";
        return "AuditLens_" + safe + "_" + java.time.LocalDate.now() + "." + ext;
    }

    public static void showAndSave(Component parent, Engine engine) {
        JTextField title = new JTextField("AuditLens Security Assessment Report", 30);
        JTextField project = new JTextField(30);
        JTextField scope = new JTextField(30);
        JTextField tester = new JTextField(30);
        JTextField org = new JTextField(30);
        final byte[][] logo = {new byte[0]};
        final String[] logoExt = {"png"};
        JLabel logoLabel = new JLabel("No logo selected");
        JButton logoBtn = new JButton("Choose logo…");
        logoBtn.addActionListener(e -> {
            JFileChooser lc = new JFileChooser();
            lc.setDialogTitle("Organization logo (PNG, JPEG or GIF, up to 2 MB)");
            lc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Images (PNG, JPEG, GIF)", "png", "jpg", "jpeg", "gif"));
            if (lc.showOpenDialog(parent) != JFileChooser.APPROVE_OPTION) return;
            java.io.File f = lc.getSelectedFile();
            String name = f.getName().toLowerCase(java.util.Locale.ROOT);
            String ext = name.endsWith(".png") ? "png" : name.endsWith(".gif") ? "gif"
                    : (name.endsWith(".jpg") || name.endsWith(".jpeg")) ? "jpeg" : null;
            if (ext == null) { JOptionPane.showMessageDialog(parent, "Choose a PNG, JPEG or GIF image."); return; }
            if (f.length() > 2_000_000) { JOptionPane.showMessageDialog(parent, "Logo is larger than 2 MB. Choose a smaller image."); return; }
            try {
                logo[0] = Files.readAllBytes(f.toPath());
                logoExt[0] = ext;
                logoLabel.setText(f.getName() + " (" + (logo[0].length / 1024) + " KB)");
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(parent, "Could not read the logo: " + ex.getMessage());
            }
        });
        JButton logoClear = new JButton("Remove");
        logoClear.addActionListener(e -> { logo[0] = new byte[0]; logoLabel.setText("No logo selected"); });
        JCheckBox info = new JCheckBox("Include informational findings", true);
        JCheckBox auditLog = new JCheckBox("Include full audit log appendix", false);
        JCheckBox evidence = new JCheckBox("Include evidence refs", true);
        JCheckBox engineInfo = new JCheckBox("Show engine information (model name) on the cover", true);
        JComboBox<String> format = new JComboBox<>(new String[]{"HTML (.html)", "Excel (.xlsx)", "Both HTML + Excel"});

        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 4, 4, 4);
        g.anchor = GridBagConstraints.WEST;
        int row = 0;
        g.gridx = 0; g.gridy = row; p.add(new JLabel("Report title"), g);
        g.gridx = 1; g.gridy = row++; p.add(title, g);
        g.gridx = 0; g.gridy = row; p.add(new JLabel("Project name (used in file name)"), g);
        g.gridx = 1; g.gridy = row++; p.add(project, g);
        g.gridx = 0; g.gridy = row; p.add(new JLabel("Target / scope (optional)"), g);
        g.gridx = 1; g.gridy = row++; p.add(scope, g);
        g.gridx = 0; g.gridy = row; p.add(new JLabel("Organization name"), g);
        g.gridx = 1; g.gridy = row++; p.add(org, g);
        g.gridx = 0; g.gridy = row; p.add(new JLabel("Organization logo"), g);
        JPanel logoRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        logoRow.add(logoBtn); logoRow.add(logoClear); logoRow.add(logoLabel);
        g.gridx = 1; g.gridy = row++; p.add(logoRow, g);
        g.gridx = 0; g.gridy = row; p.add(new JLabel("Prepared by (optional)"), g);
        g.gridx = 1; g.gridy = row++; p.add(tester, g);
        g.gridx = 0; g.gridy = row; p.add(new JLabel("Format"), g);
        g.gridx = 1; g.gridy = row++; p.add(format, g);
        g.gridx = 0; g.gridy = row++; g.gridwidth = 2; p.add(info, g);
        g.gridy = row++; p.add(evidence, g);
        g.gridy = row++; p.add(engineInfo, g);
        g.gridy = row++; p.add(auditLog, g);

        int n = engine.memory.findings().size();
        if (JOptionPane.showConfirmDialog(parent, p, "Generate report (" + n + " finding(s) recorded)",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;

        ReportOptions opt = new ReportOptions();
        opt.title = title.getText().isBlank() ? opt.title : title.getText().trim();
        opt.targetScope = scope.getText().trim();
        String projectName = project.getText().trim();
        opt.testerName = tester.getText().trim();
        opt.organization = org.getText().trim();
        opt.logoBytes = logo[0];
        opt.logoExt = logoExt[0];
        opt.includeInfo = info.isSelected();
        opt.includeAuditLog = auditLog.isSelected();
        opt.includeEvidence = evidence.isSelected();
        opt.showEngine = engineInfo.isSelected();

        int fmt = format.getSelectedIndex(); // 0 = HTML, 1 = Excel, 2 = both
        boolean wantHtml = fmt == 0 || fmt == 2;
        boolean wantXlsx = fmt == 1 || fmt == 2;

        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(defaultFileName(projectName, opt.targetScope, wantHtml ? "html" : "xlsx")));
        fc.setDialogTitle("Save report" + (fmt == 2 ? " (base name; .html and .xlsx will be written)" : ""));
        if (fc.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return;
        java.io.File chosen = fc.getSelectedFile();
        String base = chosen.getAbsolutePath().replaceFirst("(?i)\\.(html?|xlsx)$", "");

        java.util.List<java.io.File> saved = new java.util.ArrayList<>();
        try {
            if (wantHtml) {
                String html = HtmlReport.generate(opt, engine.memory.findings(), engine.audit, engine.settings, engine.evidence);
                java.io.File hf = new java.io.File(base + ".html");
                Files.writeString(hf.toPath(), html, StandardCharsets.UTF_8);
                saved.add(hf);
            }
            if (wantXlsx) {
                byte[] xlsx = ExcelReport.generate(opt, engine.memory.findings());
                java.io.File xf = new java.io.File(base + ".xlsx");
                Files.write(xf.toPath(), xlsx);
                saved.add(xf);
            }
        } catch (IOException | RuntimeException ex) {
            JOptionPane.showMessageDialog(parent, "Could not save report: " + ex.getMessage());
            return;
        }

        StringBuilder msg = new StringBuilder("Report saved:");
        for (java.io.File s2 : saved) msg.append("\n").append(s2.getAbsolutePath());
        msg.append("\n\nOpen now?");
        int openIt = JOptionPane.showConfirmDialog(parent, msg.toString(), "Report saved", JOptionPane.YES_NO_OPTION);
        if (openIt == JOptionPane.YES_OPTION) {
            for (java.io.File s2 : saved) {
                try {
                    if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN))
                        Desktop.getDesktop().open(s2);
                    else if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE))
                        Desktop.getDesktop().browse(s2.toURI());
                } catch (IOException | RuntimeException ex) {
                    JOptionPane.showMessageDialog(parent, "Could not open automatically; the file is at " + s2.getAbsolutePath());
                }
            }
        }
    }
}
