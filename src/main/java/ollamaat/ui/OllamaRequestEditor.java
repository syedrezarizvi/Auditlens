package ollamaat.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import javax.swing.*;
import java.awt.*;

/**
 * An "AuditLens" tab in Repeater (and Proxy) request editors. Its button runs AuditLens's read-only agent review on the
 * request shown. The tab is read-only: it never edits or sends the request.
 */
public final class OllamaRequestEditor implements ExtensionProvidedHttpRequestEditor {
    private final MainPanel panel;
    private final JPanel ui = new JPanel(new BorderLayout());
    private final JLabel status = new JLabel(" ");
    private HttpRequestResponse current;

    public OllamaRequestEditor(MainPanel panel) {
        this.panel = panel;
        JButton analyze = new JButton("Analyze with AuditLens");
        analyze.setToolTipText("Runs AuditLens's read-only agent review on this request (and its response, if one was captured). Sends no new requests.");
        analyze.addActionListener(e -> {
            if (current == null) { status.setText("No request loaded."); return; }
            panel.analyzeRequest(current);
            status.setText("Analysis started. Follow it in the AuditLens tab.");
        });
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(analyze);
        top.add(status);
        ui.add(top, BorderLayout.NORTH);
        ui.add(new JLabel("  Read-only: this tab does not edit or send the request."), BorderLayout.CENTER);
    }

    @Override public HttpRequest getRequest() { return current == null ? null : current.request(); }
    @Override public void setRequestResponse(HttpRequestResponse rr) { current = rr; status.setText(" "); }
    @Override public boolean isEnabledFor(HttpRequestResponse rr) { return rr != null && rr.request() != null; }
    @Override public String caption() { return "AuditLens"; }
    @Override public Component uiComponent() { return ui; }
    @Override public Selection selectedData() { return null; }
    @Override public boolean isModified() { return false; }
}
