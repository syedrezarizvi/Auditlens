package ollamaat.llm;

import ollamaat.Settings;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/** Sends each call to the provider chosen in Settings. The choice is read per call, so changing it takes effect at once. */
public final class LlmRouter implements LlmBackend {
    private final Settings settings;
    private final OllamaClient ollama;
    private final BurpAiBackend burp;

    public LlmRouter(Settings settings, OllamaClient ollama, BurpAiBackend burp) {
        this.settings = settings; this.ollama = ollama; this.burp = burp;
    }

    private LlmBackend current() {
        return Settings.PROVIDER_OLLAMA.equals(settings.llmProvider()) ? ollama : burp;
    }

    @Override
    public OllamaClient.ChatResult chat(List<Map<String, Object>> messages, List<Map<String, Object>> tools, boolean jsonOnly) throws IOException {
        return current().chat(messages, tools, jsonOnly);
    }

    @Override public void cancel() { ollama.cancel(); burp.cancel(); }

    @Override public List<String> listModels() throws IOException { return current().listModels(); }

    @Override public String version() throws IOException { return current().version(); }
}
