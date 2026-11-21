package ollamaat.llm;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * A chat backend used by the agent, the triage pass and the passive review. Two implementations exist: Burp AI
 * (the default) and a local or loopback Ollama server. Which one is used is chosen per call by {@link LlmRouter}.
 */
public interface LlmBackend {
    /**
     * @param tools Ollama-format tool definitions, or null/empty for plain chat. A backend without native tool calling
     *              throws {@link OllamaClient.ToolsUnsupportedException}, and the agent then switches to the JSON protocol.
     * @param jsonOnly ask for JSON output where the backend can enforce it.
     */
    OllamaClient.ChatResult chat(List<Map<String, Object>> messages, List<Map<String, Object>> tools, boolean jsonOnly) throws IOException;

    /** Aborts the in-flight request, if the backend supports cancellation. */
    void cancel();

    /** Model names offered by the backend. Empty when the backend picks its own model. */
    List<String> listModels() throws IOException;

    /** Short version or identity string for the connection test. */
    String version() throws IOException;
}
