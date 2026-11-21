package ollamaat.tools;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import ollamaat.Settings;
import ollamaat.agent.*;
import ollamaat.util.Json;
import ollamaat.util.Text;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.IntSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The tool surface exposed to the model. Every tool plans first; {@link Policy} decides whether it may run. */
public final class BurpTools {
    private static final Set<String> STATIC_EXT = Set.of("js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2",
            "ttf", "eot", "map", "webp", "mp4", "mp3", "pdf");

    private final MontoyaApi api;
    private final Settings settings;
    private final Evidence ev;
    private final Memory memory;
    private final SkillLibrary skills;
    private final Throttle throttle;
    private final IntSupplier runId;

    public BurpTools(MontoyaApi api, Settings settings, Evidence ev, Memory memory, SkillLibrary skills, Throttle throttle, IntSupplier runId) {
        this.api = api; this.settings = settings; this.ev = ev; this.memory = memory; this.skills = skills;
        this.throttle = throttle; this.runId = runId;
    }

    public List<Tool> all() {
        return List.of(listProxyHistory(), listEndpoints(), getMessage(), searchTraffic(), extract(), listIssues(), scopeCheck(),
                sendRequest(), replayRequest(), compareMessages(), convert(), addFinding(), noteAdd(), notesList(),
                sendToRepeater(), sendToOrganizer(), listSkills(), loadSkill(), finish());
    }

    // ------------------------------------------------------------------ helpers
    private boolean inScope(String url) { return api.scope().isInScope(url); }

    /** Resolves a ref; proxy refs must be in scope (selected/agent refs were explicitly exposed or in scope by construction). */
    private HttpRequestResponse fetch(String ref) throws ToolException {
        HttpRequestResponse rr = ev.get(ref);
        String r = ref.trim().toLowerCase().replace("#", "");
        if ((r.startsWith("p") || r.matches("\\d+")) && !inScope(rr.request().url()))
            throw new ToolException("Item " + ref + " is out of Burp target scope and cannot be read.");
        return rr;
    }

    private static HttpRequest setHeader(HttpRequest r, String k, String v) {
        return r.hasHeader(k) ? r.withUpdatedHeader(k, v) : r.withAddedHeader(k, v);
    }

    private static boolean statusMatches(String filter, int status) {
        String f = filter.trim().toLowerCase();
        if (f.matches("[1-5]xx")) return status / 100 == f.charAt(0) - '0';
        return f.equals(String.valueOf(status));
    }

    private static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>");
    }

    // ------------------------------------------------------------------ read tools
    private Tool listProxyHistory() {
        return new FnTool("list_proxy_history",
                "List IN-SCOPE Proxy history items as one-line summaries with refs (p<id>) usable by other tools. Static assets hidden by default.",
                Schema.of().str("host", "Only hosts containing this text", false).str("method", "HTTP method", false)
                        .str("status", "Status filter: 200, 3xx, 4xx, 5xx", false).str("url_regex", "Regex on the full URL", false)
                        .bool("with_params", "Only requests carrying parameters", false).bool("include_static", "Include js/css/images", false)
                        .integer("offset", "Skip the first N matches", false).integer("limit", "Rows to return (default 40, max 150)", false),
                a -> Action.read("list proxy history", () -> {
                    Pattern re = a.has("url_regex") ? Pattern.compile(a.str("url_regex", "")) : null;
                    int limit = Math.min(150, Math.max(1, a.integer("limit", 40))), off = Math.max(0, a.integer("offset", 0));
                    boolean statics = a.bool("include_static", false), params = a.bool("with_params", false);
                    String host = a.str("host", "").toLowerCase(), method = a.str("method", "").toUpperCase(), status = a.str("status", "");
                    List<ProxyHttpRequestResponse> hist = ev.proxy();
                    StringBuilder sb = new StringBuilder();
                    int matched = 0, shown = 0, inScopeTotal = 0;
                    for (ProxyHttpRequestResponse p : hist) {
                        if (!inScope(p.request().url())) continue;
                        inScopeTotal++;
                        if (!host.isEmpty() && !p.httpService().host().toLowerCase().contains(host)) continue;
                        if (!method.isEmpty() && !p.request().method().equalsIgnoreCase(method)) continue;
                        if (!statics && STATIC_EXT.contains(p.request().fileExtension().toLowerCase())) continue;
                        if (params && !p.request().hasParameters()) continue;
                        if (re != null && !re.matcher(p.request().url()).find()) continue;
                        if (!status.isEmpty() && (!p.hasResponse() || !statusMatches(status, p.response().statusCode()))) continue;
                        matched++;
                        if (matched <= off || shown >= limit) continue;
                        shown++;
                        sb.append(Fmt.line("p" + p.id(), HttpRequestResponse.httpRequestResponse(p.request(), p.hasResponse() ? p.response() : null))).append('\n');
                    }
                    String head = matched + " matching in-scope items (proxy history total " + hist.size() + "), showing " + shown + " from offset " + off + ".\n";
                    if (inScopeTotal == 0)
                        head = "No in-scope items found in " + hist.size() + " proxy items. The target must be added to Burp's target scope first.\n";
                    return head + sb;
                }));
    }

    private Tool listEndpoints() {
        return new FnTool("list_endpoints",
                "Summarise in-scope traffic as unique endpoints (method + path template), with hit counts, status codes and parameter names. Best first step for recon.",
                Schema.of().str("host", "Only hosts containing this text", false).integer("limit", "Max endpoints (default 60)", false),
                a -> Action.read("list endpoints", () -> {
                    String host = a.str("host", "").toLowerCase();
                    int limit = Math.min(200, Math.max(1, a.integer("limit", 60)));
                    class Stat { int n; Set<Integer> st = new TreeSet<>(); Set<String> pn = new TreeSet<>(); String firstRef; }
                    Map<String, Stat> map = new TreeMap<>();
                    for (ProxyHttpRequestResponse p : ev.proxy()) {
                        if (!inScope(p.request().url())) continue;
                        if (!host.isEmpty() && !p.httpService().host().toLowerCase().contains(host)) continue;
                        if (STATIC_EXT.contains(p.request().fileExtension().toLowerCase())) continue;
                        String key = p.request().method() + " " + p.httpService().host() + Text.pathTemplate(p.request().path());
                        Stat s = map.computeIfAbsent(key, k -> new Stat());
                        s.n++;
                        if (s.firstRef == null) s.firstRef = "p" + p.id();
                        if (p.hasResponse()) s.st.add((int) p.response().statusCode());
                        for (var prm : p.request().parameters()) if (s.pn.size() < 12) s.pn.add(prm.name());
                    }
                    StringBuilder sb = new StringBuilder(map.size() + " unique in-scope endpoints:\n");
                    int c = 0;
                    for (Map.Entry<String, Stat> e : map.entrySet()) {
                        if (c++ >= limit) { sb.append("…more omitted, use host filter\n"); break; }
                        Stat s = e.getValue();
                        sb.append(e.getKey()).append("  x").append(s.n).append(" status=").append(s.st).append(" params=").append(s.pn)
                                .append(" e.g. ").append(s.firstRef).append('\n');
                    }
                    return sb.toString();
                }));
    }

    private Tool getMessage() {
        return new FnTool("get_message", "Show the request and/or response for a ref (e.g. p12, a3, s1).",
                Schema.of().str("ref", "Message ref", true).str("part", "request | response | both (default both)", false)
                        .integer("max_body_chars", "Max body characters per part (default 2500)", false),
                a -> {
                    HttpRequestResponse rr = fetch(a.req("ref"));
                    String part = a.str("part", "both").toLowerCase();
                    int max = Math.max(200, a.integer("max_body_chars", 2500));
                    return Action.read("show " + a.req("ref") + " (" + part + ")", () -> {
                        boolean red = settings.redactSecrets();
                        StringBuilder sb = new StringBuilder(Fmt.line(a.req("ref"), rr)).append('\n');
                        if (!part.equals("response")) sb.append("--- REQUEST ---\n").append(Fmt.request(rr.request(), max, red)).append('\n');
                        if (!part.equals("request")) sb.append("--- RESPONSE ---\n").append(Fmt.response(rr.hasResponse() ? rr.response() : null, max, red));
                        return sb.toString();
                    });
                });
    }

    private Tool searchTraffic() {
        return new FnTool("search_traffic", "Regex search across in-scope proxy history. Returns refs with a short match snippet.",
                Schema.of().str("pattern", "Java regex (case-insensitive)", true).str("where", "request | response | both (default both)", false)
                        .integer("limit", "Max hits (default 25)", false),
                a -> {
                    Pattern re = Pattern.compile(a.req("pattern"), Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                    String where = a.str("where", "both").toLowerCase();
                    int limit = Math.min(100, Math.max(1, a.integer("limit", 25)));
                    return Action.read("search traffic /" + a.req("pattern") + "/", () -> {
                        StringBuilder sb = new StringBuilder();
                        int hits = 0, scanned = 0;
                        for (ProxyHttpRequestResponse p : ev.proxy()) {
                            if (scanned >= 8000 || hits >= limit) break;
                            if (!inScope(p.request().url())) continue;
                            scanned++;
                            String where1 = null, snippet = null;
                            if (!where.equals("response")) { snippet = snippet(re, p.request().toString()); if (snippet != null) where1 = "req"; }
                            if (snippet == null && !where.equals("request") && p.hasResponse()) { snippet = snippet(re, p.response().toString()); if (snippet != null) where1 = "resp"; }
                            if (snippet != null) { hits++; sb.append("p").append(p.id()).append(' ').append(p.request().method()).append(' ').append(p.request().url()).append(" [").append(where1).append("] …").append(snippet).append("…\n"); }
                        }
                        return hits + " hit(s) in " + scanned + " scanned items\n" + sb;
                    });
                });
    }

    private static String snippet(Pattern re, String text) {
        Matcher m = re.matcher(text);
        if (!m.find()) return null;
        int s = Math.max(0, m.start() - 40), e = Math.min(text.length(), m.end() + 40);
        return Text.oneLine(text.substring(s, e), 160);
    }

    private Tool extract() {
        return new FnTool("extract", "Extract regex matches (or capture group) from a message, e.g. tokens, ids, CSRF values, emails. Returns unique values.",
                Schema.of().str("ref", "Message ref", true).str("pattern", "Java regex", true).integer("group", "Capture group (default 0)", false)
                        .str("where", "request | response (default response)", false),
                a -> {
                    HttpRequestResponse rr = fetch(a.req("ref"));
                    Pattern re = Pattern.compile(a.req("pattern"));
                    int g = Math.max(0, a.integer("group", 0));
                    boolean req = a.str("where", "response").equalsIgnoreCase("request");
                    return Action.read("extract /" + a.req("pattern") + "/ from " + a.req("ref"), () -> {
                        String text = req ? rr.request().toString() : (rr.hasResponse() ? rr.response().toString() : "");
                        Matcher m = re.matcher(text);
                        Set<String> out = new LinkedHashSet<>();
                        while (m.find() && out.size() < 50) out.add(m.group(Math.min(g, m.groupCount())));
                        return out.isEmpty() ? "no matches" : String.join("\n", out);
                    });
                });
    }

    private Tool listIssues() {
        return new FnTool("list_issues", "List existing in-scope Burp issues (scanner findings and findings added by AuditLens).",
                Schema.of().integer("limit", "Max rows (default 40)", false),
                a -> Action.read("list issues", () -> {
                    int limit = Math.min(100, Math.max(1, a.integer("limit", 40)));
                    StringBuilder sb = new StringBuilder();
                    int n = 0;
                    for (AuditIssue i : api.siteMap().issues()) {
                        if (!inScope(i.baseUrl())) continue;
                        if (n++ >= limit) break;
                        sb.append(i.severity()).append('/').append(i.confidence()).append("  ").append(i.name()).append("  ").append(i.baseUrl()).append('\n');
                    }
                    return n == 0 ? "no issues" : sb.toString();
                }));
    }

    private Tool scopeCheck() {
        return new FnTool("scope_check", "Check whether a URL is inside Burp's target scope (requests outside scope are always blocked).",
                Schema.of().str("url", "Absolute URL", true),
                a -> Action.read("scope check " + a.req("url"), () -> inScope(a.req("url")) ? "IN scope" : "NOT in scope"));
    }

    // ------------------------------------------------------------------ network tools
    private Tool sendRequest() {
        return new FnTool("send_request",
                "Send a new HTTP request to an in-scope URL through Burp. Prefer replay_request when a similar captured request exists. Subject to approval policy and rate limits.",
                Schema.of().str("url", "Absolute http(s) URL", true).str("method", "HTTP method (default GET)", false)
                        .obj("headers", "Header name -> value", false).str("body", "Request body", false),
                a -> {
                    String method = a.str("method", "GET").toUpperCase();
                    HttpRequest req = HttpRequest.httpRequestFromUrl(a.req("url"));
                    if (!method.equals("GET")) req = req.withMethod(method);
                    for (Map.Entry<String, String> h : a.strMap("headers").entrySet()) req = setHeader(req, h.getKey(), h.getValue());
                    String body = a.str("body", null);
                    if (body != null && !body.isEmpty()) req = req.withBody(body);
                    final HttpRequest fr = req;
                    var net = new Action.NetInfo(method, fr.url(), body != null && !body.isEmpty(), Fmt.request(fr, 2000, false));
                    return Action.network("send " + method + " " + fr.url(), net, () -> sendAndDescribe(fr, null));
                });
    }

    private Tool replayRequest() {
        return new FnTool("replay_request",
                "Replay a captured request with targeted modifications (same host only). Reports how the response differs from the original. Ideal for access-control, parameter and header tests: change ONE thing per call.",
                Schema.of().str("ref", "Message ref to replay", true).str("method", "Override method", false)
                        .str("path", "Override path+query, must start with /", false)
                        .obj("query_set", "URL parameters to add/replace: name -> value", false)
                        .obj("body_params_set", "Form body parameters to add/replace: name -> value", false)
                        .obj("set_headers", "Headers to add/replace: name -> value", false)
                        .arr("remove_headers", "Header names to remove (e.g. Cookie, Authorization)", false)
                        .str("body", "Replace the entire body", false)
                        .arr("body_replace", "List of {find, replace} text substitutions applied to the body", false),
                a -> {
                    HttpRequestResponse base = fetch(a.req("ref"));
                    HttpRequest r = base.request();
                    if (a.has("method")) r = r.withMethod(a.str("method", "GET").toUpperCase());
                    if (a.has("path")) {
                        String p = a.str("path", "/");
                        if (!p.startsWith("/")) throw new ToolException("path must start with '/'");
                        r = r.withPath(p);
                    }
                    for (Map.Entry<String, String> e : a.strMap("query_set").entrySet()) r = r.withParameter(HttpParameter.urlParameter(e.getKey(), e.getValue()));
                    for (Map.Entry<String, String> e : a.strMap("body_params_set").entrySet()) r = r.withParameter(HttpParameter.bodyParameter(e.getKey(), e.getValue()));
                    for (Map.Entry<String, String> e : a.strMap("set_headers").entrySet()) r = setHeader(r, e.getKey(), e.getValue());
                    for (String h : a.strList("remove_headers")) r = r.withRemovedHeader(h);
                    if (a.has("body")) r = r.withBody(a.str("body", ""));
                    for (String[] pr : a.pairs("body_replace")) r = r.withBody(r.bodyToString().replace(pr[0], pr[1]));
                    final HttpRequest fr = r;
                    var net = new Action.NetInfo(fr.method(), fr.url(), fr.body().length() > 0, Fmt.request(fr, 2000, false));
                    String ref = a.req("ref");
                    return Action.network("replay " + ref + " as " + fr.method() + " " + fr.url(), net, () -> sendAndDescribe(fr, base));
                });
    }

    private String sendAndDescribe(HttpRequest req, HttpRequestResponse baseline) {
        throttle.acquire();
        HttpRequestResponse rr = api.http().sendRequest(req);
        String ref = ev.addAgent(rr);
        StringBuilder sb = new StringBuilder(Fmt.line(ref, rr)).append('\n');
        if (!rr.hasResponse()) return sb.append("No response received (timeout/connection error).").toString();
        HttpResponse resp = rr.response();
        String t = Fmt.title(resp);
        if (!t.isEmpty()) sb.append("title: ").append(t).append('\n');
        if (baseline != null && baseline.hasResponse()) {
            HttpResponse b = baseline.response();
            sb.append("vs baseline: status ").append(b.statusCode()).append("->").append(resp.statusCode())
                    .append(", length ").append(b.body().length()).append("->").append(resp.body().length())
                    .append(String.format(", body similarity %.2f", Fmt.similarity(b.bodyToString(), resp.bodyToString()))).append('\n');
        }
        sb.append("--- RESPONSE ---\n").append(Fmt.response(resp, Math.max(500, settings.maxOutputChars() / 2), settings.redactSecrets()));
        return sb.toString();
    }

    private Tool compareMessages() {
        return new FnTool("compare_messages", "Compare two responses: status, length, differing headers, and body lines unique to each.",
                Schema.of().str("ref_a", "First ref", true).str("ref_b", "Second ref", true),
                a -> {
                    HttpRequestResponse x = fetch(a.req("ref_a")), y = fetch(a.req("ref_b"));
                    return Action.read("compare " + a.req("ref_a") + " vs " + a.req("ref_b"), () -> {
                        if (!x.hasResponse() || !y.hasResponse()) return "One of the messages has no response.";
                        HttpResponse p = x.response(), q = y.response();
                        StringBuilder sb = new StringBuilder();
                        sb.append("status ").append(p.statusCode()).append(" vs ").append(q.statusCode()).append('\n');
                        sb.append("length ").append(p.body().length()).append(" vs ").append(q.body().length())
                                .append(String.format(", similarity %.2f\n", Fmt.similarity(p.bodyToString(), q.bodyToString())));
                        Map<String, String> hp = new TreeMap<>(), hq = new TreeMap<>();
                        p.headers().forEach(h -> hp.put(h.name().toLowerCase(), h.value()));
                        q.headers().forEach(h -> hq.put(h.name().toLowerCase(), h.value()));
                        Set<String> keys = new TreeSet<>(hp.keySet());
                        keys.addAll(hq.keySet());
                        for (String k : keys) if (!Objects.equals(hp.get(k), hq.get(k)) && !k.equals("date"))
                            sb.append("header ").append(k).append(": ").append(Text.oneLine(String.valueOf(hp.get(k)), 80)).append("  |  ").append(Text.oneLine(String.valueOf(hq.get(k)), 80)).append('\n');
                        Set<String> la = new LinkedHashSet<>(List.of(p.bodyToString().split("\\R"))), lb = new LinkedHashSet<>(List.of(q.bodyToString().split("\\R")));
                        int n = 0;
                        for (String l : la) if (!lb.contains(l) && n++ < 15) sb.append("< ").append(Text.oneLine(l, 160)).append('\n');
                        n = 0;
                        for (String l : lb) if (!la.contains(l) && n++ < 15) sb.append("> ").append(Text.oneLine(l, 160)).append('\n');
                        return sb.toString();
                    });
                });
    }

    // ------------------------------------------------------------------ utilities
    private Tool convert() {
        return new FnTool("convert", "Encode/decode helper: kind = base64 | base64url | url | hex | html | jwt (jwt: decode only, signature NOT verified).",
                Schema.of().str("value", "Input text", true).str("kind", "base64 | base64url | url | hex | html | jwt", true)
                        .str("direction", "decode (default) or encode", false),
                a -> {
                    String v = a.req("value"), kind = a.req("kind").toLowerCase();
                    boolean enc = a.str("direction", "decode").equalsIgnoreCase("encode");
                    return Action.read(kind + " " + (enc ? "encode" : "decode"), () -> {
                        switch (kind) {
                            case "base64": return enc ? Base64.getEncoder().encodeToString(v.getBytes(StandardCharsets.UTF_8)) : new String(Base64.getMimeDecoder().decode(v), StandardCharsets.UTF_8);
                            case "base64url": return enc ? Base64.getUrlEncoder().withoutPadding().encodeToString(v.getBytes(StandardCharsets.UTF_8)) : new String(Base64.getUrlDecoder().decode(v.replace("=", "")), StandardCharsets.UTF_8);
                            case "url": return enc ? URLEncoder.encode(v, StandardCharsets.UTF_8) : URLDecoder.decode(v, StandardCharsets.UTF_8);
                            case "hex": return enc ? HexFormat.of().formatHex(v.getBytes(StandardCharsets.UTF_8)) : new String(HexFormat.of().parseHex(v.replaceAll("\\s", "")), StandardCharsets.UTF_8);
                            case "html": return enc ? esc(v) : v.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&");
                            case "jwt": {
                                String[] p = v.trim().split("\\.");
                                if (p.length < 2) throw new IllegalArgumentException("not a JWT");
                                String h = new String(Base64.getUrlDecoder().decode(p[0]), StandardCharsets.UTF_8);
                                String b = new String(Base64.getUrlDecoder().decode(p[1]), StandardCharsets.UTF_8);
                                Object ho = Json.parseLenient(h), bo = Json.parseLenient(b);
                                return "header: " + (ho == null ? h : Json.pretty(ho)) + "\npayload: " + (bo == null ? b : Json.pretty(bo))
                                        + "\nsignature present: " + (p.length > 2 && !p[2].isEmpty()) + " (NOT verified)";
                            }
                            default: throw new IllegalArgumentException("unknown kind " + kind);
                        }
                    });
                });
    }

    // ------------------------------------------------------------------ project-writing tools
    private Tool addFinding() {
        return new FnTool("add_finding",
                "Record a VERIFIED security finding. It is added to the Burp site map as an issue (tagged AI-assisted) and to AuditLens's findings list. Cite evidence refs.",
                Schema.of().str("title", "Short issue title", true).str("severity", "high | medium | low | info", true)
                        .str("confidence", "certain | firm | tentative", true).str("url", "Affected URL", true)
                        .str("detail", "What was observed and why it matters, with reproduction steps", true)
                        .arr("evidence", "Refs supporting the finding, e.g. [\"p12\",\"a3\"]", true).str("remediation", "Suggested fix", false),
                a -> {
                    String title = a.req("title"), url = a.req("url"), detail = a.req("detail");
                    List<String> refs = a.strList("evidence");
                    if (refs.isEmpty()) throw new ToolException("evidence must list at least one ref");
                    for (String r : refs) fetch(r); // validate refs resolve before recording the write action
                    String severity = a.req("severity"), confidence = a.req("confidence"), remediation = a.str("remediation", "");
                    return Action.annotate("record finding: " + title + " [" + severity + "]", () -> {
                        Memory.Finding f = IssueReporter.report(api, memory, runId.getAsInt(), "agent", title, severity, confidence,
                                url, detail, remediation, refs, this::fetch);
                        return "Finding recorded in the Findings tab" + (f.reportedToBurp() ? " and added to Burp issues." : " (Burp issue add failed; it is still in the Findings tab).");
                    });
                });
    }

    private Tool noteAdd() {
        return new FnTool("note_add", "Save a durable fact for later runs (roles, tokens' locations, interesting endpoints, dead ends).",
                Schema.of().str("title", "Short title", true).str("text", "Content", true),
                a -> Action.annotate("note: " + a.req("title"), () -> { memory.addNote(runId.getAsInt(), a.req("title"), a.req("text")); return "Saved."; }));
    }

    private Tool notesList() {
        return new FnTool("notes_list", "List saved engagement notes and findings from earlier runs.", Schema.of(),
                a -> Action.read("list notes", () -> { String d = memory.digest(6000); return d.isBlank() ? "nothing saved yet" : d; }));
    }

    private Tool sendToRepeater() {
        return new FnTool("send_to_repeater", "Send a message to Burp Repeater (not executed) so the pentester can continue manually.",
                Schema.of().str("ref", "Message ref", true).str("name", "Repeater tab name", false),
                a -> {
                    HttpRequestResponse rr = fetch(a.req("ref"));
                    return Action.write("send " + a.req("ref") + " to Repeater", () -> {
                        api.repeater().sendToRepeater(rr.request(), a.str("name", "AuditLens " + a.req("ref")));
                        return "Sent to Repeater.";
                    });
                });
    }

    private Tool sendToOrganizer() {
        return new FnTool("send_to_organizer", "Save a message to Burp Organizer with a note (evidence for the report).",
                Schema.of().str("ref", "Message ref", true).str("note", "Annotation text", false),
                a -> {
                    HttpRequestResponse rr = fetch(a.req("ref"));
                    return Action.write("send " + a.req("ref") + " to Organizer", () -> {
                        api.organizer().sendToOrganizer(rr.withAnnotations(Annotations.annotations("AuditLens: " + a.str("note", ""))));
                        return "Sent to Organizer.";
                    });
                });
    }

    private Tool listSkills() {
        return new FnTool("list_skills", "List available methodology skills.", Schema.of(), a -> Action.read("list skills", skills::catalog));
    }

    private Tool loadSkill() {
        return new FnTool("load_skill", "Load a methodology skill (step-by-step testing approach) into context.", Schema.of().str("name", "Skill name", true),
                a -> {
                    SkillLibrary.Skill s = skills.get(a.req("name"));
                    if (s == null) throw new ToolException("Unknown skill. Available:\n" + skills.catalog());
                    return Action.read("load skill " + s.name(), s::body);
                });
    }

    private Tool finish() {
        return new FnTool("finish", "End the run with a final summary for the pentester.", Schema.of().str("summary", "What was tested, found, and what remains", true),
                a -> Action.finish(a.req("summary")));
    }
}
