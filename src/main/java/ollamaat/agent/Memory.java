package ollamaat.agent;

import ollamaat.util.Json;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/** Shared engagement memory (notes + findings). Persists in the Burp project so later runs start from what is known. */
public final class Memory {
    public record Note(long time, int run, String title, String text) {}
    public record Finding(long time, int run, String title, String severity, String confidence, String url,
                          String detail, String remediation, List<String> evidence, boolean reportedToBurp, String aiTriage,
                          boolean falsePositive) {
        // Back-compat constructor for callers that don't set an AI triage verdict.
        public Finding(long time, int run, String title, String severity, String confidence, String url,
                       String detail, String remediation, List<String> evidence, boolean reportedToBurp, String aiTriage) {
            this(time, run, title, severity, confidence, url, detail, remediation, evidence, reportedToBurp, aiTriage, false);
        }
        public Finding(long time, int run, String title, String severity, String confidence, String url,
                       String detail, String remediation, List<String> evidence, boolean reportedToBurp) {
            this(time, run, title, severity, confidence, url, detail, remediation, evidence, reportedToBurp, "", false);
        }
        public Finding withTriage(String verdict) {
            return new Finding(time, run, title, severity, confidence, url, detail, remediation, evidence, reportedToBurp,
                    verdict == null ? "" : verdict, falsePositive);
        }
        public Finding withFalsePositive(boolean fp) {
            return new Finding(time, run, title, severity, confidence, url, detail, remediation, evidence, reportedToBurp, aiTriage, fp);
        }
    }

    private static final String NOTES = "ollamaat.notes", FINDINGS = "ollamaat.findings";
    private final Persist persist;
    private final List<Note> notes = new CopyOnWriteArrayList<>();
    private final List<Finding> findings = new CopyOnWriteArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public Memory(Persist persist) {
        this.persist = persist;
        try {
            List<Object> l = Json.asList(Json.parse(orEmpty(persist.get(NOTES))));
            if (l != null) for (Object o : l) {
                Map<String, Object> m = Json.asMap(o);
                notes.add(new Note(((Number) m.get("t")).longValue(), ((Number) m.get("run")).intValue(), str(m, "title"), str(m, "text")));
            }
            l = Json.asList(Json.parse(orEmpty(persist.get(FINDINGS))));
            if (l != null) for (Object o : l) {
                Map<String, Object> m = Json.asMap(o);
                List<String> ev = new ArrayList<>();
                List<Object> el = Json.asList(m.get("evidence"));
                if (el != null) for (Object e : el) ev.add(String.valueOf(e));
                findings.add(new Finding(((Number) m.get("t")).longValue(), ((Number) m.get("run")).intValue(), str(m, "title"),
                        str(m, "severity"), str(m, "confidence"), str(m, "url"), str(m, "detail"), str(m, "remediation"), ev,
                        Boolean.TRUE.equals(m.get("burp")), str(m, "triage"), Boolean.TRUE.equals(m.get("falsePositive"))));
            }
        } catch (RuntimeException ignored) { /* start fresh */ }
    }

    private static String orEmpty(String s) { return s == null ? "[]" : s; }
    private static String str(Map<String, Object> m, String k) { Object o = m.get(k); return o == null ? "" : String.valueOf(o); }

    public void onChange(Runnable r) { listeners.add(r); }
    private void fire() { for (Runnable r : listeners) try { r.run(); } catch (RuntimeException ignored) { } }

    public synchronized void addNote(int run, String title, String text) {
        notes.add(new Note(System.currentTimeMillis(), run, title, text));
        List<Object> out = new ArrayList<>();
        for (Note n : notes) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("t", n.time()); m.put("run", n.run()); m.put("title", n.title()); m.put("text", n.text());
            out.add(m);
        }
        persist.set(NOTES, Json.write(out));
        fire();
    }

    /** True if a finding with the same title and URL is already recorded. */
    public boolean hasFinding(String title, String url) {
        for (Finding x : findings) if (x.title().equals(title) && x.url().equals(url)) return true;
        return false;
    }

    /** Adds f unless an identical title+URL is already recorded. Returns true if it was added. */
    public synchronized boolean addFindingIfAbsent(Finding f) {
        if (hasFinding(f.title(), f.url())) return false;
        addFinding(f);
        return true;
    }

    /** Attach (or replace) an AI false-positive triage verdict on a finding identified by title+url. Persists + fires. */
    public synchronized boolean setTriage(String title, String url, String verdict) {
        for (int i = 0; i < findings.size(); i++) {
            Finding x = findings.get(i);
            if (x.title().equals(title) && x.url().equals(url)) {
                findings.set(i, x.withTriage(verdict));
                persistFindings();
                fire();
                return true;
            }
        }
        return false;
    }

    /**
     * Marks or unmarks a finding as a manual false positive. Marked findings stay in the Findings tab but are left out
     * of every generated report. Matches the stored finding by value. Returns false if it is not recorded.
     */
    public synchronized boolean setFalsePositive(Finding target, boolean fp) {
        for (int i = 0; i < findings.size(); i++) {
            if (findings.get(i).equals(target)) {
                findings.set(i, findings.get(i).withFalsePositive(fp));
                persistFindings();
                fire();
                return true;
            }
        }
        return false;
    }

    public synchronized void addFinding(Finding f) {
        findings.add(f);
        persistFindings();
        fire();
    }

    private void persistFindings() {
        List<Object> out = new ArrayList<>();
        for (Finding x : findings) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("t", x.time()); m.put("run", x.run()); m.put("title", x.title()); m.put("severity", x.severity());
            m.put("confidence", x.confidence()); m.put("url", x.url()); m.put("detail", x.detail());
            m.put("remediation", x.remediation()); m.put("evidence", x.evidence()); m.put("burp", x.reportedToBurp());
            m.put("triage", x.aiTriage()); m.put("falsePositive", x.falsePositive());
            out.add(m);
        }
        persist.set(FINDINGS, Json.write(out));
    }

    public List<Note> notes() { return new ArrayList<>(notes); }
    public List<Finding> findings() { return new ArrayList<>(findings); }

    /** Compact digest injected into the system prompt so a new run continues from prior knowledge. */
    public String digest(int maxChars) {
        StringBuilder sb = new StringBuilder();
        for (Note n : notes) sb.append("- NOTE ").append(n.title()).append(": ").append(ollamaat.util.Text.oneLine(n.text(), 200)).append('\n');
        for (Finding f : findings) sb.append("- FINDING [").append(f.severity()).append("] ").append(f.title()).append(" @ ").append(f.url()).append('\n');
        String s = sb.toString();
        return s.length() > maxChars ? s.substring(s.length() - maxChars) : s;
    }
}
