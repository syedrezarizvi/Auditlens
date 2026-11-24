package ollamaat;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import ollamaat.ui.MainPanel;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/**
 * AuditLens: agentic, policy-controlled AI testing inside Burp Suite. The model is Burp AI by default, or a local
 * Ollama server when chosen in Settings.
 */
public class AuditLens implements BurpExtension {
    private MontoyaApi api;
    private Engine engine;
    private MainPanel panel;

    /**
     * Declare AI support. Without this flag Burp keeps {@code api.ai()} disabled, so Burp AI — AuditLens's default
     * provider — would never work and the per-extension "Use AI" checkbox would not appear. Required by the BApp
     * Store AI extension best practices.
     */
    @Override
    public java.util.Set<EnhancedCapability> enhancedCapabilities() {
        return java.util.Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AuditLens");
        engine = new Engine(api);
        panel = new MainPanel(engine);
        api.userInterface().registerSuiteTab("AuditLens", panel);
        api.userInterface().registerContextMenuItemsProvider(new Menu());
        api.userInterface().registerHttpRequestEditorProvider(ctx -> new ollamaat.ui.OllamaRequestEditor(panel));
        try {
            api.scanner().registerPassiveScanCheck(new AiPassiveCheck(engine), ScanCheckType.PER_REQUEST);
        } catch (RuntimeException e) {
            api.logging().logToOutput("AuditLens: scanner checks unavailable in this edition (" + e.getMessage() + ")");
        }
        api.extension().registerUnloadingHandler(() -> engine.unload());
        boolean ollama = Settings.PROVIDER_OLLAMA.equals(engine.settings.llmProvider());
        api.logging().logToOutput("AuditLens loaded. Model provider: " + (ollama ? "local Ollama" : "Burp AI")
                + ". Configure it in the AuditLens > Settings tab.");
        if (!ollama)
            api.logging().logToOutput("AuditLens: Burp AI sends prompts to PortSwigger's AI service. Choose Local Ollama in Settings to keep engagement data on this machine.");
        if (ollama && !engine.settings.isLoopbackOllama() && !engine.settings.allowRemoteHost())
            api.logging().raiseErrorEvent("AuditLens: Ollama URL is not loopback and remote hosts are not allowed. Review Settings.");
    }

    private final class Menu implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> items = new ArrayList<>(event.selectedRequestResponses());
            if (items.isEmpty() && event.messageEditorRequestResponse().isPresent())
                items.add(event.messageEditorRequestResponse().get().requestResponse());
            if (items.isEmpty()) return List.of();

            JMenu menu = new JMenu("AuditLens");
            JMenuItem add = new JMenuItem("Add to agent context");
            add.addActionListener(e -> panel.addContext(items));
            JMenuItem explain = new JMenuItem("Review selected (read-only)");
            explain.addActionListener(e -> {
                panel.addContext(items);
                panel.startRun("Review the selected messages for security weaknesses visible in them (use the refs in the context). "
                        + "Explain the purpose of each request, note risky parameters, tokens, headers and data exposure, and suggest "
                        + "concrete follow-up tests. Do not send requests.", true);
            });
            JMenuItem test = new JMenuItem("Investigate with agent…");
            test.addActionListener(e -> {
                String t = JOptionPane.showInputDialog(api.userInterface().swingUtils().suiteFrame(), "What should the agent investigate?",
                        "Test the selected requests for broken access control and parameter handling weaknesses using minimal, non-destructive probes.");
                if (t != null && !t.isBlank()) { panel.addContext(items); panel.startRun(t, false); }
            });
            JMenuItem scan = new JMenuItem("Active scan selected…");
            scan.addActionListener(e -> panel.scanFromContextMenu(items));
            menu.add(add); menu.add(explain); menu.add(test); menu.add(scan);
            return List.of(menu);
        }

        /** Burp's Issues panel: "Send to AuditLens" runs the local model's false-positive analysis on the selected issues. */
        @Override
        public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
            List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues = new ArrayList<>(event.selectedIssues());
            if (issues.isEmpty()) return List.of();
            JMenuItem ai = new JMenuItem("Send to AuditLens for AI analysis (" + issues.size() + ")");
            ai.setToolTipText("Imports the selected Burp issue(s) into AuditLens's Findings tab and runs the local model's false-positive analysis on them. Sends no requests.");
            ai.addActionListener(e -> panel.analyzeBurpIssues(issues));
            JMenuItem investigate = new JMenuItem("Investigate with AuditLens agent");
            investigate.setEnabled(issues.size() == 1);
            investigate.setToolTipText(issues.size() == 1
                    ? "Runs the AuditLens agent (read-only) on this issue and its captured requests. Sends no requests."
                    : "Select a single issue to investigate.");
            investigate.addActionListener(e -> panel.investigateIssue(issues.get(0)));
            return List.of(ai, investigate);
        }
    }
}
