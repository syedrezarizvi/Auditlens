package ollamaat;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/** User-level settings. Backed by Burp Preferences in production, or a plain map in tests. */
public final class Settings {
    public enum Autonomy { STRICT, SMART, AUTONOMOUS }

    /** Model providers. Burp AI is the default; Ollama keeps all inference on a local or loopback server. */
    public static final String PROVIDER_BURP = "burp", PROVIDER_OLLAMA = "ollama";

    public interface Store {
        String get(String key);
        void set(String key, String value);
    }

    public static Store memoryStore() {
        Map<String, String> m = new HashMap<>();
        return new Store() {
            public String get(String k) { return m.get(k); }
            public void set(String k, String v) { m.put(k, v); }
        };
    }

    private final Store store;
    public Settings(Store store) { this.store = store; }

    private String s(String k, String d) { String v = store.get("ollamaat." + k); return v == null ? d : v; }
    private void put(String k, Object v) { store.set("ollamaat." + k, String.valueOf(v)); }
    private <T> T parse(String k, T d, Function<String, T> f) {
        try { return f.apply(s(k, String.valueOf(d))); } catch (RuntimeException e) { return d; }
    }

    /** {@link #PROVIDER_BURP} (default) or {@link #PROVIDER_OLLAMA}. Any other stored value reads as Burp AI. */
    public String llmProvider() { return PROVIDER_OLLAMA.equals(s("provider", PROVIDER_BURP)) ? PROVIDER_OLLAMA : PROVIDER_BURP; }
    public void llmProvider(String v) { put("provider", PROVIDER_OLLAMA.equals(v) ? PROVIDER_OLLAMA : PROVIDER_BURP); }
    public String ollamaUrl() { return s("url", "http://127.0.0.1:11434"); }
    public void ollamaUrl(String v) { put("url", v.trim().replaceAll("/+$", "")); }
    public String model() { return s("model", ""); }
    public void model(String v) { put("model", v == null ? "" : v); }
    public String apiKey() { return s("apiKey", ""); }
    public void apiKey(String v) { put("apiKey", v); }
    public double temperature() { return parse("temp", 0.2, Double::parseDouble); }
    public void temperature(double v) { put("temp", v); }
    public int numCtx() { return parse("numCtx", 16384, Integer::parseInt); }
    public void numCtx(int v) { put("numCtx", v); }
    public String keepAlive() { return s("keepAlive", "30m"); }
    public int timeoutSec() { return parse("timeout", 300, Integer::parseInt); }
    public void timeoutSec(int v) { put("timeout", v); }
    public int maxSteps() { return parse("maxSteps", 40, Integer::parseInt); }
    public void maxSteps(int v) { put("maxSteps", v); }
    public int maxOutputChars() { return parse("maxOut", 6000, Integer::parseInt); }
    public void maxOutputChars(int v) { put("maxOut", v); }
    public Autonomy autonomy() { return parse("autonomy", Autonomy.SMART, Autonomy::valueOf); }
    public void autonomy(Autonomy v) { put("autonomy", v); }
    public int maxRequestsPerRun() { return parse("maxReq", 150, Integer::parseInt); }
    public void maxRequestsPerRun(int v) { put("maxReq", v); }
    public double requestsPerSecond() { return parse("rps", 4.0, Double::parseDouble); }
    public void requestsPerSecond(double v) { put("rps", v); }
    public int approvalTimeoutSec() { return parse("approvalTimeout", 600, Integer::parseInt); }
    /** One regex per line. A request URL matching any line is hard-blocked. */
    public String blockedPatterns() {
        return s("blocked", "(?i)(log-?out|sign-?out|delete[-_]?account|deactivate|close[-_]?account)").replace("\\n", "\n");
    }
    public void blockedPatterns(String v) { put("blocked", v.replace("\n", "\\n")); }
    public String skillsDir() { return s("skillsDir", ""); }
    public void skillsDir(String v) { put("skillsDir", v); }
    public boolean aiPassiveScan() { return parse("passive", false, Boolean::parseBoolean); }
    public void aiPassiveScan(boolean v) { put("passive", v); }
    /** Force the JSON-in-text tool protocol (for models without native tool calling). */
    public boolean forceJsonMode() { return parse("jsonMode", false, Boolean::parseBoolean); }
    public void forceJsonMode(boolean v) { put("jsonMode", v); }
    public boolean allowRemoteHost() { return parse("allowRemote", false, Boolean::parseBoolean); }
    public void allowRemoteHost(boolean v) { put("allowRemote", v); }
    public boolean redactSecrets() { return parse("redact", false, Boolean::parseBoolean); }
    public void redactSecrets(boolean v) { put("redact", v); }

    public boolean isLoopbackOllama() {
        try {
            String h = URI.create(ollamaUrl()).getHost();
            if (h == null) return false;
            return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("::1") || h.equals("[::1]");
        } catch (RuntimeException e) { return false; }
    }
}
