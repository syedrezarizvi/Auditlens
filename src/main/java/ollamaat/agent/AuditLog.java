package ollamaat.agent;

import ollamaat.util.Json;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/** Append-only record of every tool call, the policy verdict and who decided. Persisted in the Burp project. */
public final class AuditLog {
    public record Entry(long time, int run, String tool, String summary, String verdict, String by, String outcome) {}

    private static final String KEY = "ollamaat.audit";
    private static final int MAX = 3000;
    private final List<Entry> entries = new CopyOnWriteArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private final Persist persist;

    public AuditLog(Persist persist) {
        this.persist = persist;
        try {
            List<Object> l = Json.asList(Json.parse(persist.get(KEY) == null ? "[]" : persist.get(KEY)));
            if (l != null) for (Object o : l) {
                Map<String, Object> m = Json.asMap(o);
                if (m == null) continue;
                entries.add(new Entry(((Number) m.get("t")).longValue(), ((Number) m.get("run")).intValue(), s(m, "tool"),
                        s(m, "summary"), s(m, "verdict"), s(m, "by"), s(m, "outcome")));
            }
        } catch (RuntimeException ignored) { /* corrupt log: start fresh */ }
    }

    private static String s(Map<String, Object> m, String k) { Object o = m.get(k); return o == null ? "" : String.valueOf(o); }

    public void onChange(Runnable r) { listeners.add(r); }

    public synchronized void add(int run, String tool, String summary, String verdict, String by, String outcome) {
        entries.add(new Entry(System.currentTimeMillis(), run, tool, summary, verdict, by, outcome));
        while (entries.size() > MAX) entries.remove(0);
        save();
        for (Runnable r : listeners) try { r.run(); } catch (RuntimeException ignored) { }
    }

    public List<Entry> all() { return new ArrayList<>(entries); }

    private void save() {
        List<Object> out = new ArrayList<>();
        for (Entry e : entries) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("t", e.time()); m.put("run", e.run()); m.put("tool", e.tool()); m.put("summary", e.summary());
            m.put("verdict", e.verdict()); m.put("by", e.by()); m.put("outcome", e.outcome());
            out.add(m);
        }
        try { persist.set(KEY, Json.write(out)); } catch (RuntimeException ignored) { }
    }

    public String toMarkdown() {
        StringBuilder sb = new StringBuilder("| Time | Run | Tool | Action | Verdict | Decided by | Outcome |\n|---|---|---|---|---|---|---|\n");
        for (Entry e : entries)
            sb.append("| ").append(Instant.ofEpochMilli(e.time())).append(" | ").append(e.run()).append(" | ").append(e.tool())
                    .append(" | ").append(e.summary().replace("|", "\\|").replace("\n", " ")).append(" | ").append(e.verdict())
                    .append(" | ").append(e.by()).append(" | ").append(e.outcome().replace("|", "\\|").replace("\n", " ")).append(" |\n");
        return sb.toString();
    }
}
