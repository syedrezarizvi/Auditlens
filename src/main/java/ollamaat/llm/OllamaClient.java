package ollamaat.llm;

import ollamaat.Settings;
import ollamaat.util.Json;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/** Talks to a local Ollama server (/api/chat, /api/tags). No credits, no cloud. */
public final class OllamaClient implements LlmBackend {
    @SuppressWarnings("serial")
    public static final class ToolsUnsupportedException extends IOException {
        public ToolsUnsupportedException(String m) { super(m); }
    }

    public record ToolCall(String name, Map<String, Object> args) {}

    public record ChatResult(String content, List<ToolCall> toolCalls, Map<String, Object> assistantMessage,
                             long promptTokens, long evalTokens) {}

    private final Settings settings;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private volatile CompletableFuture<?> inflight;

    public OllamaClient(Settings settings) { this.settings = settings; }

    private void guardHost() throws IOException {
        if (!settings.isLoopbackOllama() && !settings.allowRemoteHost())
            throw new IOException("Ollama URL " + settings.ollamaUrl() + " is not loopback. Tick 'Allow remote Ollama host' in Settings "
                    + "to confirm that engagement data may leave this machine.");
    }

    private HttpRequest.Builder req(String path) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(settings.ollamaUrl() + path))
                .timeout(Duration.ofSeconds(Math.max(5, settings.timeoutSec())))
                .header("Content-Type", "application/json");
        if (!settings.apiKey().isBlank()) b.header("Authorization", "Bearer " + settings.apiKey());
        return b;
    }

    private HttpResponse<String> send(HttpRequest r) throws IOException {
        CompletableFuture<HttpResponse<String>> f = http.sendAsync(r, HttpResponse.BodyHandlers.ofString());
        inflight = f;
        try {
            return f.get();
        } catch (CancellationException e) {
            throw new IOException("cancelled");
        } catch (InterruptedException e) {
            f.cancel(true);
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        } catch (ExecutionException e) {
            Throwable c = e.getCause() == null ? e : e.getCause();
            throw new IOException("Cannot reach Ollama at " + settings.ollamaUrl() + ": " + c.getMessage(), c);
        } finally {
            inflight = null;
        }
    }

    /** Aborts the in-flight request, if any. */
    public void cancel() {
        CompletableFuture<?> f = inflight;
        if (f != null) f.cancel(true);
    }

    public List<String> listModels() throws IOException {
        guardHost();
        HttpResponse<String> r = send(req("/api/tags").GET().build());
        if (r.statusCode() != 200) throw new IOException("Ollama /api/tags returned HTTP " + r.statusCode());
        List<String> out = new ArrayList<>();
        Map<String, Object> m = Json.asMap(Json.parse(r.body()));
        List<Object> models = m == null ? null : Json.asList(m.get("models"));
        if (models != null) for (Object o : models) {
            Map<String, Object> mm = Json.asMap(o);
            if (mm != null && mm.get("name") != null) out.add(String.valueOf(mm.get("name")));
        }
        Collections.sort(out);
        return out;
    }

    public String version() throws IOException {
        guardHost();
        HttpResponse<String> r = send(req("/api/version").GET().build());
        Map<String, Object> m = Json.asMap(Json.parse(r.body()));
        return m == null ? "?" : String.valueOf(m.get("version"));
    }

    /** @param tools Ollama-format tool definitions, or null/empty for plain chat. @param jsonOnly constrain output to JSON. */
    public ChatResult chat(List<Map<String, Object>> messages, List<Map<String, Object>> tools, boolean jsonOnly) throws IOException {
        guardHost();
        if (settings.model().isBlank()) throw new IOException("No Ollama model selected (Settings tab).");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", settings.model());
        body.put("messages", messages);
        body.put("stream", false);
        if (tools != null && !tools.isEmpty()) body.put("tools", tools);
        if (jsonOnly) body.put("format", "json");
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("temperature", settings.temperature());
        opts.put("num_ctx", settings.numCtx());
        body.put("options", opts);
        body.put("keep_alive", settings.keepAlive());

        HttpResponse<String> r = send(req("/api/chat").POST(HttpRequest.BodyPublishers.ofString(Json.write(body))).build());
        if (r.statusCode() != 200) {
            String b = r.body() == null ? "" : r.body();
            if (r.statusCode() == 400 && b.toLowerCase().contains("does not support tools"))
                throw new ToolsUnsupportedException(settings.model() + " does not support native tool calling");
            throw new IOException("Ollama HTTP " + r.statusCode() + ": " + b);
        }
        Map<String, Object> resp = Json.asMap(Json.parse(r.body()));
        Map<String, Object> msg = resp == null ? null : Json.asMap(resp.get("message"));
        if (msg == null) throw new IOException("Malformed Ollama response: " + r.body());
        String content = msg.get("content") == null ? "" : String.valueOf(msg.get("content"));
        List<ToolCall> calls = new ArrayList<>();
        List<Object> tc = Json.asList(msg.get("tool_calls"));
        if (tc != null) for (Object o : tc) {
            Map<String, Object> fn = Json.asMap(Json.asMap(o) == null ? null : Json.asMap(o).get("function"));
            if (fn == null) continue;
            Object a = fn.get("arguments");
            Map<String, Object> args = new LinkedHashMap<>();
            if (a instanceof Map) args = Json.asMap(a);
            else if (a instanceof String) {
                Map<String, Object> p = Json.asMap(Json.parseLenient((String) a));
                if (p != null) args = p;
            }
            calls.add(new ToolCall(String.valueOf(fn.get("name")), args));
        }
        Map<String, Object> keep = new LinkedHashMap<>();
        keep.put("role", "assistant");
        keep.put("content", content);
        if (tc != null && !tc.isEmpty()) keep.put("tool_calls", tc);
        return new ChatResult(content, calls, keep, num(resp.get("prompt_eval_count")), num(resp.get("eval_count")));
    }

    private static long num(Object o) { return o instanceof Number ? ((Number) o).longValue() : 0; }
}
