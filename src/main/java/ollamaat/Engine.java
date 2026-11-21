package ollamaat;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import ollamaat.agent.*;
import ollamaat.llm.BurpAiBackend;
import ollamaat.llm.LlmRouter;
import ollamaat.llm.MontoyaAiPrompter;
import ollamaat.llm.OllamaClient;
import ollamaat.scan.ActiveScanEngine;
import ollamaat.scan.ScanCheck;
import ollamaat.scan.ScanFinding;
import ollamaat.tools.BurpTools;
import ollamaat.tools.Evidence;
import ollamaat.tools.Fmt;
import ollamaat.tools.IssueReporter;
import ollamaat.tools.Throttle;
import ollamaat.triage.Triage;
import ollamaat.util.Text;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/** Wires Burp, Ollama, policy, memory and the agent together. One agent run at a time. */
public final class Engine {
    public final MontoyaApi api;
    public final Settings settings;
    public final LlmRouter llm;
    public final Memory memory;
    public final AuditLog audit;
    public final Approvals approvals = new Approvals();
    public final Evidence evidence;
    private final Throttle throttle;
    private final Policy policy;
    private final AtomicInteger runSeq = new AtomicInteger();
    private volatile SkillLibrary skills;
    private volatile Agent active;
    private volatile ActiveScanEngine activeScan;
    private volatile Thread worker;
    private volatile int currentRun;

    private static final Set<String> NETWORK_TOOLS = Set.of("send_request", "replay_request");

    public Engine(MontoyaApi api) {
        this.api = api;
        var prefs = api.persistence().preferences();
        this.settings = new Settings(new Settings.Store() {
            public String get(String k) { return prefs.getString(k); }
            public void set(String k, String v) { prefs.setString(k, v); }
        });
        var ext = api.persistence().extensionData();
        Persist p = new Persist() {
            public String get(String k) { return ext.getString(k); }
            public void set(String k, String v) { ext.setString(k, v); }
        };
        this.memory = new Memory(p);
        this.audit = new AuditLog(p);
        this.llm = new LlmRouter(settings, new OllamaClient(settings), new BurpAiBackend(new MontoyaAiPrompter(api)));
        this.evidence = new Evidence(api);
        this.throttle = new Throttle(settings);
        this.policy = new Policy(settings, api.scope()::isInScope);
        this.skills = SkillLibrary.load(settings.skillsDir());
    }

    public SkillLibrary skills() { return skills; }
    public void reloadSkills() { skills = SkillLibrary.load(settings.skillsDir()); }
    public boolean busy() { Thread t = worker; return t != null && t.isAlive(); }

    private Agent buildAgent(Agent.Listener l) {
        List<Tool> tools = new BurpTools(api, settings, evidence, memory, skills, throttle, () -> currentRun).all();
        return new Agent(settings, llm, tools, policy, approvals, audit, memory, skills, l);
    }

    /** Starts a run on a background thread. Returns false if one is already active. */
    public synchronized boolean start(String task, List<String> preloadSkills, String context, boolean allowNetwork,
                                      Agent.Listener listener, Runnable onDone) {
        if (busy()) return false;
        int id = runSeq.incrementAndGet();
        currentRun = id;
        RunState rs = new RunState(id);
        rs.allowNetwork = allowNetwork;
        Agent a = buildAgent(listener);
        active = a;
        Thread t = new Thread(() -> {
            try {
                a.run(rs, task, preloadSkills, context, name -> allowNetwork || !NETWORK_TOOLS.contains(name));
            } catch (Throwable e) {
                api.logging().logToError("AuditLens run failed", e);
            } finally {
                synchronized (Engine.this) { active = null; worker = null; }
                if (onDone != null) onDone.run();
            }
        }, "AuditLens-run-" + id);
        t.setDaemon(true);
        worker = t;
        t.start();
        return true;
    }

    private final java.util.List<Runnable> unloadHooks = new java.util.concurrent.CopyOnWriteArrayList<>();
    public void onUnload(Runnable r) { unloadHooks.add(r); }
    public void unload() { stop(); for (Runnable r : unloadHooks) try { r.run(); } catch (RuntimeException ignored) { } }

    public void stop() {
        Agent a = active;
        if (a != null) a.cancel();
        ActiveScanEngine s = activeScan;
        if (s != null) s.cancel();
    }

    // ------------------------------------------------------------------ active scan
    public List<ScanCheck> scanChecks() { return ActiveScanEngine.allChecks(); }

    public int estimateScanRequests(List<HttpRequestResponse> endpoints, List<ScanCheck> checks) {
        return ActiveScanEngine.estimateRequests(endpoints, checks);
    }

    /** Starts a deterministic active scan on a background thread. Returns false if a run is already active. */
    public synchronized boolean startActiveScan(List<HttpRequestResponse> endpoints, List<ScanCheck> checks, boolean allowNetwork,
                                                ActiveScanEngine.Listener listener, Runnable onDone) {
        if (busy()) return false;
        int id = runSeq.incrementAndGet();
        currentRun = id;
        ActiveScanEngine eng = new ActiveScanEngine(api, settings, evidence, policy, approvals, audit, throttle);
        activeScan = eng;
        ActiveScanEngine.Listener wrapped = new ActiveScanEngine.Listener() {
            public void event(ActiveScanEngine.EventType t, String s) { listener.event(t, s); }
            public void finding(ScanFinding f) {
                listener.finding(f);
                try {
                    IssueReporter.report(api, memory, id, "active-scan", f.title(), f.severity(), f.confidence(), f.url(),
                            f.detail(), f.remediation(), f.evidence(), evidence::get);
                } catch (ToolException e) {
                    api.logging().logToError("AuditLens: failed to record scan finding: " + e.getMessage());
                }
            }
        };
        Thread t = new Thread(() -> {
            try {
                eng.scan(id, endpoints, checks, allowNetwork, wrapped);
            } catch (Throwable e) {
                api.logging().logToError("AuditLens active scan failed", e);
            } finally {
                synchronized (Engine.this) { activeScan = null; worker = null; }
                if (onDone != null) onDone.run();
            }
        }, "AuditLens-scan-" + id);
        t.setDaemon(true);
        worker = t;
        t.start();
        return true;
    }

    // ------------------------------------------------------------------ on-demand AI review (self-driven)
    public interface ReviewListener {
        void event(String tag, String text);
        default void done(int reviewed, int findings) {}
    }

    private final PassiveReviewer reviewer = new PassiveReviewer(this);

    /** Reviews up to maxItems distinct in-scope proxy exchanges with the local model, writing findings to the
     *  Findings tab and Burp issues. Sends NO new requests. Independent of Burp's passive scanner. Background thread. */
    public synchronized boolean startProxyReview(int maxItems, boolean inScopeOnly, ReviewListener l, Runnable onDone) {
        if (busy()) return false;
        if (settings.model().isBlank()) { l.event("ERROR", "No Ollama model selected (Settings tab)."); return false; }
        int id = runSeq.incrementAndGet();
        currentRun = id;
        Thread t = new Thread(() -> {
            int reviewed = 0, found = 0;
            try {
                java.util.List<burp.api.montoya.proxy.ProxyHttpRequestResponse> hist = evidence.proxy();
                java.util.Set<String> seen = new java.util.HashSet<>();
                java.util.List<HttpRequestResponse> todo = new java.util.ArrayList<>();
                for (var p : hist) {
                    if (!p.hasResponse()) continue;
                    String url = p.finalRequest().url();
                    if (inScopeOnly && !api.scope().isInScope(url)) continue;
                    String ct = Fmt.contentType(p.response());
                    if (ct.startsWith("image") || ct.startsWith("font") || ct.startsWith("video") || ct.startsWith("audio")) continue;
                    String key = p.finalRequest().method() + " " + p.httpService().host()
                            + Text.pathTemplate(p.finalRequest().path()) + " " + p.response().statusCode() + " " + ct;
                    if (!seen.add(key)) continue;
                    todo.add(HttpRequestResponse.httpRequestResponse(p.finalRequest(), p.response()));
                    if (todo.size() >= maxItems) break;
                }
                l.event("START", todo.size() + " distinct " + (inScopeOnly ? "in-scope " : "") + "exchange(s) to review"
                        + (hist.isEmpty() ? " (proxy history is empty — browse the target through Burp first)" : "") + ".");
                for (HttpRequestResponse rr : todo) {
                    if (id != currentRun) { l.event("DONE", "Cancelled."); break; }
                    String url = rr.request().url();
                    l.event("REVIEW", rr.request().method() + " " + url);
                    try {
                        java.util.List<PassiveReviewer.Obs> obs = reviewer.review(rr);
                        reviewed++;
                        for (PassiveReviewer.Obs o : obs) {
                            if (memory.hasFinding(o.name(), url)) continue;
                            String ref = evidence.addSelected(rr);
                            String detail = o.detail() + (o.evidence().isBlank() ? "" : "\nEvidence: " + o.evidence());
                            IssueReporter.report(api, memory, id, "ai-review", o.name(), o.severity(), "tentative", url,
                                    detail, "", java.util.List.of(ref), evidence::get);
                            found++;
                            l.event("FOUND", "[" + o.severity().toUpperCase() + "] " + o.name() + "  (" + url + ")");
                        }
                    } catch (Exception e) {
                        l.event("ERROR", "review failed for " + url + ": " + e.getMessage());
                    }
                }
                l.event("DONE", "Review complete. " + reviewed + " reviewed, " + found + " finding(s).");
            } catch (Throwable e) {
                api.logging().logToError("AuditLens proxy review failed", e);
                l.event("ERROR", String.valueOf(e.getMessage()));
            } finally {
                final int fr = reviewed, ff = found;
                synchronized (Engine.this) { worker = null; }
                l.done(fr, ff);
                if (onDone != null) onDone.run();
            }
        }, "AuditLens-review-" + id);
        t.setDaemon(true);
        worker = t;
        t.start();
        return true;
    }

    /**
     * Copies every "[AI] ..." issue in Burp's Issues list into AuditLens's Findings (skipping ones already there).
     * Covers issues raised by older builds, by the passive check, or before the tab existed. Returns how many were added.
     */
    /**
     * Runs AI false-positive analysis over recorded findings using the local model: for each finding (optionally only
     * those imported from Burp), it sends the title, description and the captured request/response and asks the model
     * to judge TRUE POSITIVE / FALSE POSITIVE / NEEDS REVIEW with a short rationale, then stores that verdict on the
     * finding (visible in the Findings tab and the reports). Sends NO new requests. Background thread.
     */
    public synchronized boolean startFalsePositiveAnalysis(boolean burpOnly, boolean onlyUntriaged, ReviewListener l, Runnable onDone) {
        if (busy()) return false;
        java.util.List<Memory.Finding> todo = new java.util.ArrayList<>();
        for (Memory.Finding f : memory.findings()) {
            if (burpOnly && !f.reportedToBurp()) continue;
            if (onlyUntriaged && !f.aiTriage().isBlank()) continue;
            todo.add(f);
        }
        return startTriage(todo, l, onDone);
    }

    /** Runs the triage on the given findings, re-judging any that already have a verdict. Background thread. */
    public synchronized boolean triageFindings(java.util.List<Memory.Finding> list, ReviewListener l, Runnable onDone) {
        if (busy()) return false;
        return startTriage(new java.util.ArrayList<>(list), l, onDone);
    }

    /**
     * Burp "Send to AuditLens": imports the selected Burp issues as findings (de-duplicated) and runs the AI triage on them.
     * Sends no new requests; it only uses the evidence Burp already captured.
     */
    public synchronized boolean analyzeIssues(java.util.List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues,
                                              ReviewListener l, Runnable onDone) {
        if (busy()) return false;
        java.util.List<Memory.Finding> todo = new java.util.ArrayList<>();
        for (var issue : issues) {
            try {
                Memory.Finding f = findingFromBurpIssue(issue);
                if (f == null) continue;
                memory.addFindingIfAbsent(f);
                todo.add(f);
            } catch (RuntimeException e) {
                api.logging().logToError("AuditLens: could not import a selected Burp issue: " + e);
            }
        }
        return startTriage(todo, l, onDone);
    }

    private boolean startTriage(java.util.List<Memory.Finding> todo, ReviewListener l, Runnable onDone) {
        if (settings.model().isBlank()) { l.event("ERROR", "No Ollama model selected (Settings tab)."); return false; }
        int id = runSeq.incrementAndGet();
        currentRun = id;
        Thread t = new Thread(() -> {
            int done = 0, fp = 0, tp = 0, review = 0;
            try {
                l.event("START", todo.size() + " finding(s) to analyze for false positives.");
                for (Memory.Finding f : todo) {
                    if (id != currentRun) { l.event("DONE", "Cancelled."); break; }
                    l.event("REVIEW", f.title());
                    String verdict;
                    try {
                        verdict = triageOne(f);
                    } catch (Exception e) {
                        l.event("ERROR", "triage failed for " + f.title() + ": " + e.getMessage());
                        continue;
                    }
                    memory.setTriage(f.title(), f.url(), verdict);
                    done++;
                    String up = verdict.toUpperCase();
                    if (up.startsWith("FALSE")) { fp++; l.event("FOUND", "FALSE POSITIVE: " + f.title()); }
                    else if (up.startsWith("TRUE")) tp++;
                    else review++;
                }
                l.event("DONE", "Triage complete. " + done + " analyzed — " + tp + " true positive, " + fp
                        + " false positive, " + review + " needs review.");
            } catch (Throwable e) {
                api.logging().logToError("AuditLens false-positive analysis failed", e);
                l.event("ERROR", String.valueOf(e.getMessage()));
            } finally {
                final int d = done, f2 = fp;
                synchronized (Engine.this) { worker = null; }
                l.done(d, f2);
                if (onDone != null) onDone.run();
            }
        }, "AuditLens-fp-" + id);
        t.setDaemon(true);
        worker = t;
        t.start();
        return true;
    }

    private String triageOne(Memory.Finding f) throws Exception {
        Triage.Input in = triageInput(f);
        return Triage.analyze(in, prompt -> {
            java.util.Map<String, Object> msg = new java.util.LinkedHashMap<>();
            msg.put("role", "user"); msg.put("content", prompt);
            return llm.chat(java.util.List.of(msg), null, true).content();
        }).render();
    }

    /** Everything the triage may look at: the captured headers and body for rule checks, plus evidence text for the model. */
    private Triage.Input triageInput(Memory.Finding f) {
        java.util.List<String> reqH = new java.util.ArrayList<>(), respH = new java.util.ArrayList<>();
        String body = "";
        StringBuilder ev = new StringBuilder();
        for (String ref : f.evidence()) {
            if (ev.length() > 8000) break;
            try {
                HttpRequestResponse rr = evidence.forFinding(ref, java.util.List.of(f.url()));
                if (rr == null) continue;
                String reqText = Fmt.request(rr.request(), 1200, true);
                ev.append("REQUEST:\n").append(reqText).append("\n\n");
                if (reqH.isEmpty()) for (var h : rr.request().headers()) reqH.add(h.name() + ": " + h.value());
                if (rr.hasResponse()) {
                    var resp = rr.response();
                    if (respH.isEmpty()) for (var h : resp.headers()) respH.add(h.name() + ": " + h.value());
                    String full = resp.bodyToString();
                    if (full == null) full = "";
                    if (body.isEmpty()) body = full;
                    ev.append("RESPONSE:\n").append(Fmt.response(resp, 1500, true)).append("\n");
                    ev.append(valueWindows(full, reqText)).append("\n");
                }
            } catch (Exception ignored) { }
        }
        if (ev.length() == 0) ev.append("(no captured request/response available; judge from the finding text and URL)\n");
        return new Triage.Input(f.title(), f.severity(), f.url(), f.detail(), reqH, respH, body, ev.toString());
    }

    /**
     * Shows the model the part of the response that echoes a request parameter. A short head of the body often misses
     * the reflection that actually matters, which is one reason earlier verdicts were wrong.
     */
    static String valueWindows(String body, String reqText) {
        if (body == null || body.isEmpty() || reqText == null) return "";
        StringBuilder out = new StringBuilder();
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("[?&][^=&\\s]{1,64}=([^&\\s]{4,200})").matcher(reqText);
        java.util.Set<String> seen = new java.util.HashSet<>();
        int n = 0;
        while (m.find() && n < 3) {
            String v = m.group(1);
            try { v = java.net.URLDecoder.decode(v, "UTF-8"); } catch (Exception ignored) { }
            if (!seen.add(v)) continue;
            int at = body.indexOf(v);
            if (at < 0) continue;
            int from = Math.max(0, at - 250), to = Math.min(body.length(), at + v.length() + 250);
            out.append("WINDOW around the echoed value '").append(Text.truncate(v, 80)).append("':\n")
               .append(body, from, to).append("\n");
            n++;
        }
        return out.toString();
    }

    /**
     * Sends each finding's captured request to Burp Repeater so the tester can validate it by hand. Falls back to the
     * finding's URL when nothing was captured. Sends nothing itself; Repeater sends only when the tester does.
     */
    public int sendToRepeater(java.util.List<Memory.Finding> list) {
        int sent = 0;
        for (Memory.Finding f : list) {
            try {
                burp.api.montoya.http.message.requests.HttpRequest req = null;
                for (String ref : f.evidence()) {
                    HttpRequestResponse rr = evidence.forFinding(ref, java.util.List.of(f.url()));
                    if (rr != null) { req = rr.request(); break; }
                }
                if (req == null && f.url() != null && !f.url().isBlank())
                    req = burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(f.url());
                if (req == null) continue;
                api.repeater().sendToRepeater(req, "AuditLens: " + Text.truncate(f.title(), 60));
                sent++;
            } catch (RuntimeException e) {
                api.logging().logToError("AuditLens: could not send a finding to Repeater: " + e);
            }
        }
        return sent;
    }

    /** Auto-sync path: pulls only AuditLens's own "[AI] ..." issues from Burp. */
    public int syncFindingsFromBurp() { return importBurpIssues(true); }

    /**
     * Imports Burp scanner issues into AuditLens's Findings tab (and therefore its reports), so findings raised by
     * Burp's own active/passive scans and by other extensions appear alongside AuditLens's. onlyAiTagged=true keeps
     * the old behaviour (only "[AI] ..." issues); false imports every issue Burp has recorded. De-duplicated by
     * title+URL. Returns how many were newly added.
     */
    public int importBurpIssues(boolean onlyAiTagged) {
        int added = 0, scanned = 0;
        java.util.List<burp.api.montoya.scanner.audit.issues.AuditIssue> issues;
        try {
            issues = api.siteMap().issues();
        } catch (RuntimeException e) {
            api.logging().logToError("AuditLens: could not read Burp issues: " + e);
            return 0;
        }
        for (var issue : issues) {
            try {
                String name = issue.name();
                if (name == null || name.isBlank()) continue;
                boolean aiTagged = name.startsWith("[AI]");
                if (onlyAiTagged && !aiTagged) continue;
                scanned++;
                String title = aiTagged ? name.substring(4).trim() : name.trim();
                String url = issue.baseUrl() == null ? "" : issue.baseUrl();
                if (memory.hasFinding(title, url)) continue;
                Memory.Finding f = findingFromBurpIssue(issue);
                if (f != null && memory.addFindingIfAbsent(f)) added++;
            } catch (RuntimeException e) {
                api.logging().logToError("AuditLens: skipped one Burp issue during import: " + e);
            }
        }
        api.logging().logToOutput("AuditLens: imported " + added + " new finding(s) from Burp ("
                + (onlyAiTagged ? "[AI]-tagged only" : "all issues") + "; " + scanned + " scanned).");
        return added;
    }

    /** Converts a Burp issue into an AuditLens finding, capturing up to three request/response pairs as evidence. */
    private Memory.Finding findingFromBurpIssue(burp.api.montoya.scanner.audit.issues.AuditIssue issue) {
        String name = issue.name();
        if (name == null || name.isBlank()) return null;
        boolean aiTagged = name.startsWith("[AI]");
        String title = aiTagged ? name.substring(4).trim() : name.trim();
        String url = issue.baseUrl() == null ? "" : issue.baseUrl();
        java.util.List<String> refs = new java.util.ArrayList<>();
        var rrs = issue.requestResponses();
        if (rrs != null)
            for (int i = 0; i < rrs.size() && refs.size() < 3; i++) {
                try { refs.add(evidence.addSelected(rrs.get(i))); } catch (RuntimeException ignored) { }
            }
        String conf = issue.confidence() == null ? "TENTATIVE" : issue.confidence().name();
        String sev = issue.severity() == null ? "INFORMATION" : issue.severity().name();
        String detail = htmlToText(issue.detail());
        if (detail.isBlank()) detail = htmlToText(background(issue));
        if (detail.isBlank()) detail = "Reported by Burp Suite's scanner. See Burp's Issues panel for full detail.";
        String rem = htmlToText(issue.remediation());
        if (rem.isBlank()) rem = htmlToText(remediationBackground(issue));
        return new Memory.Finding(System.currentTimeMillis(), 0, title, sev, conf, url, detail, rem, refs, true);
    }

    private static String background(burp.api.montoya.scanner.audit.issues.AuditIssue issue) {
        try { return issue.definition() == null ? "" : issue.definition().background(); } catch (RuntimeException e) { return ""; }
    }
    private static String remediationBackground(burp.api.montoya.scanner.audit.issues.AuditIssue issue) {
        try { return issue.definition() == null ? "" : issue.definition().remediation(); } catch (RuntimeException e) { return ""; }
    }

    /** One-line explanation of why passive findings may not be arriving, for the Findings tab. */
    public String passiveStatus() {
        if (!settings.aiPassiveScan()) return "AI passive scan is OFF (Settings tab) – only Active Scan / agent findings will appear.";
        if (settings.model().isBlank()) return "AI passive scan is on but NO MODEL is selected (Settings tab).";
        return "AI passive scan ON, model " + settings.model() + ". Needs new in-scope proxy traffic and Burp tasks resumed (Dashboard).";
    }

    private static String htmlToText(String html) {
        if (html == null) return "";
        return html.replaceAll("(?i)<br\\s*/?>|</p>", "\n").replaceAll("<[^>]+>", "")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&").trim();
    }

    /** Registers messages as evidence and returns a short description (with refs) to give the model. */
    public String describe(List<HttpRequestResponse> items) {
        StringBuilder sb = new StringBuilder();
        for (HttpRequestResponse rr : items) {
            String ref = evidence.addSelected(rr);
            sb.append(Fmt.line(ref, rr)).append('\n');
            String t = rr.hasResponse() ? Fmt.title(rr.response()) : "";
            if (!t.isEmpty()) sb.append("   title: ").append(Text.oneLine(t, 80)).append('\n');
        }
        return sb.toString();
    }
}
