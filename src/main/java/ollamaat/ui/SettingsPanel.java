package ollamaat.ui;

import ollamaat.Engine;
import ollamaat.Settings;
import ollamaat.agent.Policy;

import javax.swing.*;
import java.awt.*;
import java.util.List;

@SuppressWarnings("serial")
public final class SettingsPanel extends JPanel {
    private final Engine engine;
    private final JTextField url = new JTextField(32), skillsDir = new JTextField(32);
    private final JComboBox<String> model = new JComboBox<>();
    private final JComboBox<String> provider = new JComboBox<>(new String[]{
            "Burp AI (default; prompts go to PortSwigger's AI service)",
            "Local Ollama (engagement data stays on this machine)"});
    private final JPasswordField apiKey = new JPasswordField(32);
    private final JSpinner temp = new JSpinner(new SpinnerNumberModel(0.2, 0.0, 2.0, 0.1));
    private final JSpinner ctx = new JSpinner(new SpinnerNumberModel(16384, 2048, 262144, 1024));
    private final JSpinner timeout = new JSpinner(new SpinnerNumberModel(300, 10, 3600, 10));
    private final JSpinner steps = new JSpinner(new SpinnerNumberModel(40, 1, 500, 1));
    private final JSpinner outChars = new JSpinner(new SpinnerNumberModel(6000, 500, 60000, 500));
    private final JSpinner maxReq = new JSpinner(new SpinnerNumberModel(150, 1, 5000, 10));
    private final JSpinner rps = new JSpinner(new SpinnerNumberModel(4.0, 0.1, 50.0, 0.5));
    private final JTextArea blocked = new JTextArea(4, 32);
    private final JCheckBox passive = new JCheckBox("AI passive scan of in-scope responses (uses your local model during scans)");
    private final JCheckBox jsonMode = new JCheckBox("Force JSON tool protocol (for models without native tool calling)");
    private final JCheckBox remote = new JCheckBox("Allow non-loopback Ollama host (engagement data leaves this machine)");
    private final JCheckBox redact = new JCheckBox("Redact Authorization/Cookie/API-key header values before the model sees them");
    private final JLabel info = new JLabel(" ");

    public SettingsPanel(Engine engine) {
        super(new BorderLayout());
        this.engine = engine;
        model.setEditable(true);
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 4, 3, 4);
        g.anchor = GridBagConstraints.WEST;
        int[] row = {0};
        add(form, g, row, "Model provider", provider);
        add(form, g, row, "Ollama URL (Local Ollama only)", url);
        JButton refresh = new JButton("Refresh models");
        refresh.addActionListener(e -> refreshModels());
        JPanel mp = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        model.setPreferredSize(new Dimension(300, 26));
        mp.add(model); mp.add(Box.createHorizontalStrut(6)); mp.add(refresh);
        add(form, g, row, "Model (Local Ollama only; needs tool support, e.g. qwen3, llama3.1)", mp);
        add(form, g, row, "API key (optional, for proxied Ollama)", apiKey);
        add(form, g, row, "Temperature", temp);
        add(form, g, row, "Context window (num_ctx)", ctx);
        add(form, g, row, "LLM timeout (s)", timeout);
        add(form, g, row, "Max agent steps", steps);
        add(form, g, row, "Max tool output chars", outChars);
        add(form, g, row, "Max requests per run", maxReq);
        add(form, g, row, "Requests per second", rps);
        add(form, g, row, "Hard-blocked URL regexes (one per line)", new JScrollPane(blocked));
        add(form, g, row, "Custom skills folder (*.md)", skillsDir);
        for (JCheckBox c : new JCheckBox[]{passive, jsonMode, remote, redact}) {
            g.gridx = 0; g.gridy = row[0]++; g.gridwidth = 2;
            form.add(c, g);
            g.gridwidth = 1;
        }
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton test = new JButton("Test connection"), save = new JButton("Save");
        test.addActionListener(e -> { save(); testConnection(); });
        save.addActionListener(e -> { save(); info.setText("Saved."); });
        btns.add(test); btns.add(save); btns.add(info);
        g.gridx = 0; g.gridy = row[0]++; g.gridwidth = 2;
        form.add(btns, g);
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.add(form, BorderLayout.NORTH);
        add(new JScrollPane(wrap), BorderLayout.CENTER);
        load();
    }

    private void add(JPanel p, GridBagConstraints g, int[] row, String label, JComponent c) {
        g.gridx = 0; g.gridy = row[0]; g.fill = GridBagConstraints.NONE;
        p.add(new JLabel(label), g);
        g.gridx = 1;
        g.fill = c instanceof JTextField || c instanceof JScrollPane ? GridBagConstraints.HORIZONTAL : GridBagConstraints.NONE;
        g.weightx = 1;
        p.add(c, g);
        g.weightx = 0;
        row[0]++;
    }

    private void load() {
        Settings s = engine.settings;
        provider.setSelectedIndex(Settings.PROVIDER_OLLAMA.equals(s.llmProvider()) ? 1 : 0);
        url.setText(s.ollamaUrl());
        model.setSelectedItem(s.model());
        apiKey.setText(s.apiKey());
        temp.setValue(s.temperature());
        ctx.setValue(s.numCtx());
        timeout.setValue(s.timeoutSec());
        steps.setValue(s.maxSteps());
        outChars.setValue(s.maxOutputChars());
        maxReq.setValue(s.maxRequestsPerRun());
        rps.setValue(s.requestsPerSecond());
        blocked.setText(s.blockedPatterns());
        skillsDir.setText(s.skillsDir());
        passive.setSelected(s.aiPassiveScan());
        jsonMode.setSelected(s.forceJsonMode());
        remote.setSelected(s.allowRemoteHost());
        redact.setSelected(s.redactSecrets());
    }

    private void save() {
        Settings s = engine.settings;
        List<String> bad = Policy.validatePatterns(blocked.getText());
        if (!bad.isEmpty()) { info.setText("Invalid regex ignored at runtime: " + bad.get(0)); }
        s.llmProvider(provider.getSelectedIndex() == 1 ? Settings.PROVIDER_OLLAMA : Settings.PROVIDER_BURP);
        s.ollamaUrl(url.getText());
        Object m = model.getSelectedItem();
        s.model(m == null ? "" : m.toString().trim());
        s.apiKey(new String(apiKey.getPassword()));
        s.temperature(((Number) temp.getValue()).doubleValue());
        s.numCtx(((Number) ctx.getValue()).intValue());
        s.timeoutSec(((Number) timeout.getValue()).intValue());
        s.maxSteps(((Number) steps.getValue()).intValue());
        s.maxOutputChars(((Number) outChars.getValue()).intValue());
        s.maxRequestsPerRun(((Number) maxReq.getValue()).intValue());
        s.requestsPerSecond(((Number) rps.getValue()).doubleValue());
        s.blockedPatterns(blocked.getText());
        s.skillsDir(skillsDir.getText().trim());
        s.aiPassiveScan(passive.isSelected());
        s.forceJsonMode(jsonMode.isSelected());
        s.allowRemoteHost(remote.isSelected());
        s.redactSecrets(redact.isSelected());
        engine.reloadSkills();
    }

    private void refreshModels() {
        save();
        info.setText("Contacting Ollama…");
        new Thread(() -> {
            try {
                List<String> models = engine.llm.listModels();
                SwingUtilities.invokeLater(() -> {
                    Object cur = model.getSelectedItem();
                    model.removeAllItems();
                    for (String x : models) model.addItem(x);
                    if (cur != null && !cur.toString().isBlank()) model.setSelectedItem(cur);
                    else if (!models.isEmpty()) model.setSelectedIndex(0);
                    info.setText(models.size() + " model(s) found. Remember to Save.");
                });
            } catch (Exception ex) { SwingUtilities.invokeLater(() -> info.setText("Error: " + ex.getMessage())); }
        }, "AuditLens-models").start();
    }

    private void testConnection() {
        info.setText("Testing…");
        new Thread(() -> {
            try {
                String v = engine.llm.version();
                int n = engine.llm.listModels().size();
                SwingUtilities.invokeLater(() -> info.setText("OK: " + v + (n > 0 ? ", " + n + " model(s)." : ".")));
            } catch (Exception ex) { SwingUtilities.invokeLater(() -> info.setText("Error: " + ex.getMessage())); }
        }, "AuditLens-test").start();
    }
}
