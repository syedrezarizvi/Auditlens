package ollamaat.agent;

/** Minimal string key/value persistence. In Burp this is the project's extensionData. */
public interface Persist {
    String get(String key);
    void set(String key, String value);

    static Persist memory() {
        java.util.Map<String, String> m = new java.util.concurrent.ConcurrentHashMap<>();
        return new Persist() {
            public String get(String k) { return m.get(k); }
            public void set(String k, String v) { m.put(k, v); }
        };
    }
}
