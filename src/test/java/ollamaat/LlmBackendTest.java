package ollamaat;

import ollamaat.llm.BurpAiBackend;
import ollamaat.llm.LlmRouter;
import ollamaat.llm.OllamaClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Burp AI is the default provider; Ollama is used only when chosen; Burp AI maps messages and refuses native tools. */
public final class LlmBackendTest {
    /** Records what was sent and replies with a fixed text. */
    static final class FakePrompter implements BurpAiBackend.Prompter {
        boolean enabled = true;
        int calls = 0;
        List<Map<String, Object>> last = List.of();
        public boolean enabled() { return enabled; }
        public String send(List<Map<String, Object>> messages) throws IOException {
            calls++;
            last = new ArrayList<>(messages);
            return "reply";
        }
    }

    public static void main(String[] a) throws Exception {
        int fails = 0;

        // Settings: Burp AI by default, Ollama only when chosen, unknown values fall back to Burp AI
        Settings s = new Settings(Settings.memoryStore());
        fails += check(s.llmProvider().equals(Settings.PROVIDER_BURP), "default provider is Burp AI");
        s.llmProvider(Settings.PROVIDER_OLLAMA);
        fails += check(s.llmProvider().equals(Settings.PROVIDER_OLLAMA), "Ollama can be chosen");
        s.llmProvider("something-else");
        fails += check(s.llmProvider().equals(Settings.PROVIDER_BURP), "unknown provider reads as Burp AI");

        // Burp AI backend: plain chat, message roles preserved, reply returned
        FakePrompter p = new FakePrompter();
        BurpAiBackend burp = new BurpAiBackend(p);
        List<Map<String, Object>> conv = List.of(
                Map.of("role", "system", "content", "sys"),
                Map.of("role", "user", "content", "task"),
                Map.of("role", "assistant", "content", "earlier"),
                Map.of("role", "tool", "content", "<tool_output>x</tool_output>"));
        OllamaClient.ChatResult r = burp.chat(conv, null, true);
        fails += check(r.content().equals("reply") && p.calls == 1, "Burp AI returns the reply");
        fails += check(r.assistantMessage().get("role").equals("assistant") && r.toolCalls().isEmpty(), "result is an assistant turn with no tool calls");
        fails += check(p.last.size() == 4 && p.last.get(0).get("role").equals("system") && p.last.get(3).get("role").equals("tool"),
                "messages are passed in order with their roles");

        // Native tools are refused, so the agent switches to the JSON protocol
        fails += throwsType("tool request raises ToolsUnsupportedException", OllamaClient.ToolsUnsupportedException.class,
                () -> burp.chat(conv, List.of(Map.of("type", "function")), false));

        // Disabled Burp AI gives a clear error, even when tools are requested
        p.enabled = false;
        fails += throwsWithText("disabled Burp AI reports that it is not enabled", "not enabled",
                () -> burp.chat(conv, null, true));
        fails += throwsWithText("disabled Burp AI is reported as such even with tools", "not enabled",
                () -> burp.chat(conv, List.of(Map.of("type", "function")), false));
        p.enabled = true;

        // Router: Burp AI by default; Ollama when chosen (unreachable here, so the error names Ollama and Burp is not called)
        FakePrompter q = new FakePrompter();
        Settings fresh = new Settings(Settings.memoryStore());
        LlmRouter router = new LlmRouter(fresh, new OllamaClient(fresh), new BurpAiBackend(q));
        fails += check(router.chat(conv, null, true).content().equals("reply") && q.calls == 1, "router sends to Burp AI by default");
        fresh.llmProvider(Settings.PROVIDER_OLLAMA);
        fresh.ollamaUrl("http://127.0.0.1:1");
        int before = q.calls;
        fails += throwsWithText("router sends to Ollama when chosen", "Ollama",
                () -> router.chat(conv, null, true));
        fails += check(q.calls == before, "Burp AI is not called when Ollama is chosen");

        System.out.println(fails == 0 ? "LlmBackendTest: all checks passed" : "LlmBackendTest: " + fails + " check(s) failed");
        if (fails > 0) System.exit(1);
    }

    interface Action { void run() throws Exception; }

    private static int throwsType(String name, Class<? extends Throwable> type, Action act) {
        try { act.run(); return check(false, name); }
        catch (Throwable t) { return check(type.isInstance(t), name); }
    }

    private static int throwsWithText(String name, String text, Action act) {
        try { act.run(); return check(false, name); }
        catch (Throwable t) { return check(t.getMessage() != null && t.getMessage().contains(text), name); }
    }

    private static int check(boolean ok, String name) {
        System.out.println((ok ? "PASS " : "FAIL ") + name);
        return ok ? 0 : 1;
    }
}
