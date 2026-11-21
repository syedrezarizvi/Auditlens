package ollamaat.llm;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Burp AI as a chat backend. Burp's prompt API is plain text: it has no native tool calling and no output-format
 * constraint, so tool requests are refused with {@link OllamaClient.ToolsUnsupportedException} and the agent runs the
 * JSON-in-text protocol instead. Burp AI prompts cannot be cancelled from an extension, so {@link #cancel()} does nothing.
 */
public final class BurpAiBackend implements LlmBackend {

    /** Sends a conversation to Burp AI and returns the reply. Production code wraps {@code api.ai().prompt()}. */
    public interface Prompter {
        boolean enabled();
        String send(List<Map<String, Object>> messages) throws IOException;
    }

    private final Prompter prompter;

    public BurpAiBackend(Prompter prompter) { this.prompter = prompter; }

    @Override
    public OllamaClient.ChatResult chat(List<Map<String, Object>> messages, List<Map<String, Object>> tools, boolean jsonOnly) throws IOException {
        requireEnabled();
        if (tools != null && !tools.isEmpty())
            throw new OllamaClient.ToolsUnsupportedException("Burp AI does not support native tool calling");
        String content = prompter.send(messages);
        if (content == null) content = "";
        Map<String, Object> assistant = new LinkedHashMap<>();
        assistant.put("role", "assistant");
        assistant.put("content", content);
        return new OllamaClient.ChatResult(content, List.of(), assistant, 0, 0);
    }

    @Override public void cancel() { /* Burp AI prompts cannot be cancelled from an extension. */ }

    @Override public List<String> listModels() { return List.of(); }

    @Override
    public String version() throws IOException {
        requireEnabled();
        return "Burp AI";
    }

    private void requireEnabled() throws IOException {
        if (!prompter.enabled())
            throw new IOException("Burp AI is not enabled. Enable it in Burp's settings, or choose Local Ollama in AuditLens > Settings.");
    }
}
