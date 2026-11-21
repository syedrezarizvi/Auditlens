package ollamaat.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.PromptException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Production {@link BurpAiBackend.Prompter}: converts chat maps to Burp AI messages and calls {@code api.ai().prompt()}. */
public final class MontoyaAiPrompter implements BurpAiBackend.Prompter {
    private final MontoyaApi api;

    public MontoyaAiPrompter(MontoyaApi api) { this.api = api; }

    @Override
    public boolean enabled() {
        return api.ai().isEnabled();
    }

    @Override
    public String send(List<Map<String, Object>> messages) throws IOException {
        List<Message> out = new ArrayList<>();
        for (Map<String, Object> m : messages) {
            String role = String.valueOf(m.getOrDefault("role", "user"));
            String content = m.get("content") == null ? "" : String.valueOf(m.get("content"));
            switch (role) {
                case "system" -> out.add(Message.systemMessage(content));
                case "assistant" -> out.add(Message.assistantMessage(content));
                default -> out.add(Message.userMessage(content)); // user turns and tool results
            }
        }
        try {
            return api.ai().prompt().execute(out.toArray(Message[]::new)).content();
        } catch (PromptException e) {
            throw new IOException("Burp AI request failed: " + e.getMessage(), e);
        }
    }
}
