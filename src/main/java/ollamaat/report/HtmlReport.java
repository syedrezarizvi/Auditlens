package ollamaat.report;

import ollamaat.Settings;
import ollamaat.agent.AuditLog;
import ollamaat.agent.Memory;
import ollamaat.tools.Evidence;
import ollamaat.tools.Fmt;
import ollamaat.util.Text;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Builds a single self-contained HTML report: a cover page, executive summary, findings index and numbered finding
 * sections, with an AuditLens-specific design (no template, no external fonts, scripts or network calls). Collapsible
 * evidence uses native details/summary, so no JavaScript is required.
 */
public final class HtmlReport {
    private static final List<String> SEVERITY_ORDER = List.of("HIGH", "MEDIUM", "LOW", "INFORMATION");
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm").withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("d MMMM yyyy").withZone(ZoneId.systemDefault());
    private static final int MAX_POC = 25;

    private HtmlReport() {}

    public static String generate(ReportOptions opt, List<Memory.Finding> findings, AuditLog audit, Settings settings, Evidence evidence) {
        // One entry per issue name (duplicates merged, all affected URLs listed).
        List<FindingGroup> groups = FindingGroup.of(findings, opt.includeInfo);
        int affectedTotal = 0;
        for (FindingGroup g : groups) affectedTotal += Math.max(1, g.urls.size());

        Map<String, Long> counts = new LinkedHashMap<>();
        for (String s : SEVERITY_ORDER) counts.put(s, 0L);
        for (FindingGroup g : groups) counts.merge(g.severity.toUpperCase(Locale.ROOT), 1L, Long::sum);
        String overall = groups.isEmpty() ? "None" : cap(groups.get(0).severity.toUpperCase(Locale.ROOT));
        Summary summary = Summary.of(groups);

        StringBuilder h = new StringBuilder(16_000);
        h.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
         .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
         .append("<meta name=\"generator\" content=\"AuditLens\">")
         .append("<title>").append(esc(opt.title)).append("</title><style>").append(CSS).append("</style></head><body>");

        // ---- Cover
        h.append("<header class=\"cover\"><div class=\"cover-inner\">");
        if (opt.logoBytes != null && opt.logoBytes.length > 0)
            h.append("<img class=\"logo\" alt=\"Organization logo\" src=\"data:image/").append(esc(opt.logoExt)).append(";base64,")
             .append(Base64.getEncoder().encodeToString(opt.logoBytes)).append("\">");
        if (opt.organization != null && !opt.organization.isBlank())
            h.append("<div class=\"org\">").append(esc(opt.organization.trim())).append("</div>");
        h.append("<div class=\"kicker\">Security assessment report</div>")
         .append("<h1>").append(esc(opt.title)).append("</h1>")
         .append("<div class=\"cover-sub\">").append(opt.targetScope.isBlank() ? "" : esc(opt.targetScope)).append("</div>")
         .append("<dl class=\"facts\">");
        fact(h, "Report date", DAY.format(Instant.now()));
        if (!opt.testerName.isBlank()) fact(h, "Prepared by", esc(opt.testerName));
        fact(h, "Overall rating", overall);
        fact(h, "Issues / URLs", groups.size() + " issue(s), " + affectedTotal + " affected location(s)");
        fact(h, "Highest CVSS (estimate)", summary.topScore == 0.0 ? "Not scored"
                : String.format(Locale.ROOT, "%.1f (%s)", summary.topScore, Cvss.ratingOf(summary.topScore)));
        if (opt.showEngine)
            fact(h, "Engine", ollamaat.Settings.PROVIDER_OLLAMA.equals(settings.llmProvider())
                ? "AuditLens, local model " + esc(settings.model().isBlank() ? "not set" : settings.model())
                : "AuditLens with Burp AI");
        h.append("</dl><div class=\"classification\">CONFIDENTIAL &middot; Prepared for the client named in the scope. Do not distribute.</div>")
         .append("</div></header>");

        // ---- Executive summary
        h.append("<main>");
        h.append("<section class=\"exec\"><h2><span class=\"num\">1</span>Executive summary</h2>");
        if (groups.isEmpty()) {
            h.append("<p class=\"lede\">No findings were recorded for this assessment, so no risk rating can be given.</p>");
        } else {
            String scoreNote = summary.topScore > 0
                    ? ", and the highest suggested CVSS v3.1 base score is <strong>"
                      + String.format(Locale.ROOT, "%.1f", summary.topScore) + " (" + Cvss.ratingOf(summary.topScore) + ")</strong>"
                    : "";
            h.append("<p class=\"lede\">This assessment recorded <strong>").append(summary.issues).append(" distinct issue(s)</strong> affecting ")
             .append(summary.locations).append(" location(s). The highest reported severity is <strong>").append(overall)
             .append("</strong>").append(scoreNote).append(".</p>");
            h.append("<p>").append(severityBreakdown(counts)).append("</p>");
            if (!summary.topRisks.isEmpty()) {
                h.append("<div class=\"subtle-title\">Highest-priority issues</div><ol class=\"top-risks\">");
                for (FindingGroup g : summary.topRisks)
                    h.append("<li><strong>").append(esc(g.title)).append("</strong> &mdash; CVSS ")
                     .append(String.format(Locale.ROOT, "%.1f", g.score().base())).append(" (").append(g.score().rating()).append("), ")
                     .append(Math.max(1, g.urls.size())).append(g.urls.size() == 1 ? " location" : " locations").append("</li>");
                h.append("</ol>");
            }
            h.append("<p><strong>Business impact.</strong> ").append(esc(summary.businessImpact)).append("</p>");
            h.append("<p><strong>Remediation priority.</strong> Fix high-severity issues within 7 days, medium within 30 days and low within 90 days. "
                    + "Informational items belong in the hardening backlog.</p>");
        }
        h.append("<div class=\"bars\">");
        long max = Math.max(1, counts.values().stream().mapToLong(Long::longValue).max().orElse(1));
        for (String s : SEVERITY_ORDER) {
            long c = counts.get(s);
            h.append("<div class=\"bar-row\"><span class=\"bar-label sev-").append(s.toLowerCase(Locale.ROOT)).append("\">").append(cap(s)).append("</span>")
             .append("<span class=\"bar-track\"><span class=\"bar-fill sev-").append(s.toLowerCase(Locale.ROOT))
             .append("\" style=\"width:").append(c == 0 ? 0 : Math.max(4, Math.round(100.0 * c / max))).append("%\"></span></span>")
             .append("<span class=\"bar-count\">").append(c).append("</span></div>");
        }
        h.append("</div>");
        h.append("<div class=\"subtle-title\">Management summary by severity</div>");
        h.append("<table class=\"mgmt\"><thead><tr><th>Severity</th><th class=\"c-n\">Issues</th><th class=\"c-n\">Share</th>")
         .append("<th class=\"c-n\">Affected locations</th><th>Target timeline</th></tr></thead><tbody>");
        for (Summary.Row r : summary.rows) {
            h.append("<tr><td><span class=\"pill sev-").append(r.severity().toLowerCase(Locale.ROOT)).append("\">")
             .append(cap(r.severity())).append("</span></td>")
             .append("<td class=\"c-n\">").append(r.issues()).append("</td>")
             .append("<td class=\"c-n\">").append(share(r.issues(), summary.issues)).append("</td>")
             .append("<td class=\"c-n\">").append(r.locations()).append("</td>")
             .append("<td>").append(esc(r.timeline())).append("</td></tr>");
        }
        h.append("<tr class=\"total\"><td><strong>Total</strong></td><td class=\"c-n\"><strong>").append(summary.issues)
         .append("</strong></td><td class=\"c-n\">").append(share(summary.issues, summary.issues))
         .append("</td><td class=\"c-n\"><strong>").append(summary.locations).append("</strong></td><td></td></tr>");
        h.append("</tbody></table>");
        h.append("<p class=\"caveat\"><strong>Verification note.</strong> Findings marked as automated or AI-assisted are advisory. "
                + "Each must be verified manually before it is relied upon; local model analysis and scan heuristics can both produce false positives and false negatives.</p>");
        h.append("</section>");

        // ---- Findings index
        h.append("<section class=\"index\"><h2><span class=\"num\">2</span>Findings overview</h2>");
        if (groups.isEmpty()) {
            h.append("<p class=\"muted\">No findings recorded.</p>");
        } else {
            h.append("<table class=\"index-table\"><thead><tr><th class=\"c-id\">ID</th><th>Finding</th><th class=\"c-sev\">Severity</th><th class=\"c-cv\">CVSS</th>")
             .append("<th class=\"c-n\">Locations</th><th class=\"c-ai\">AI triage</th></tr></thead><tbody>");
            for (int i = 0; i < groups.size(); i++) {
                FindingGroup g = groups.get(i);
                String sev = g.severity.toUpperCase(Locale.ROOT);
                h.append("<tr><td class=\"c-id\"><a href=\"#").append(fid(i)).append("\">").append(fid(i)).append("</a></td>")
                 .append("<td><a href=\"#").append(fid(i)).append("\">").append(esc(g.title)).append("</a></td>")
                 .append("<td class=\"c-sev\"><span class=\"pill sev-").append(sev.toLowerCase(Locale.ROOT)).append("\">").append(cap(sev)).append("</span></td>")
                 .append("<td class=\"c-cv\">").append(cvssCell(g.score())).append("</td>")
                 .append("<td class=\"c-n\">").append(Math.max(1, g.urls.size())).append("</td>")
                 .append("<td class=\"c-ai\">").append(triageLabel(g.aiTriage)).append("</td></tr>");
            }
            h.append("</tbody></table>");
        }
        h.append("</section>");

        // ---- Detailed findings
        h.append("<section class=\"details\"><h2><span class=\"num\">3</span>Detailed findings</h2>");
        if (groups.isEmpty()) h.append("<p class=\"muted\">No findings recorded.</p>");
        for (int i = 0; i < groups.size(); i++) renderFinding(h, fid(i), groups.get(i), opt, evidence);
        h.append("</section>");

        // ---- Audit log (optional appendix)
        if (opt.includeAuditLog && audit != null) {
            h.append("<section class=\"appendix\"><h2><span class=\"num\">4</span>Audit log</h2>")
             .append("<p class=\"muted\">Every tool call, policy verdict and approval decision recorded during this engagement.</p>")
             .append("<table class=\"audit\"><thead><tr><th>Time</th><th>Run</th><th>Tool</th><th>Action</th><th>Verdict</th><th>Decided by</th><th>Outcome</th></tr></thead><tbody>");
            for (AuditLog.Entry e : audit.all())
                h.append("<tr><td>").append(TS.format(Instant.ofEpochMilli(e.time()))).append("</td><td>").append(e.run())
                 .append("</td><td>").append(esc(e.tool())).append("</td><td>").append(esc(Text.oneLine(e.summary(), 160)))
                 .append("</td><td><span class=\"tag tag-").append(e.verdict().toLowerCase(Locale.ROOT)).append("\">").append(esc(e.verdict()))
                 .append("</span></td><td>").append(esc(e.by())).append("</td><td>").append(esc(Text.oneLine(e.outcome(), 160))).append("</td></tr>");
            h.append("</tbody></table></section>");
        }

        // ---- Method and limits
        h.append("<section class=\"method\"><h2><span class=\"num\">").append(opt.includeAuditLog && audit != null ? "5" : "4")
         .append("</span>Method and limitations</h2>")
         .append("<p>Testing used passive analysis of captured traffic, targeted checks, and read-only AI review by a local language model. "
                 + "Ratings reflect the evidence recorded at the time of testing. Suggested CVSS v3.1 base scores are estimates derived from each finding's category and reported severity, not measured results. Remediation guidance is generic and must be adapted to the application's architecture.</p>")
         .append("</section>");
        h.append("</main>");

        h.append("<footer><span>AuditLens &middot; ").append(esc(opt.title)).append("</span><span>Generated ")
         .append(TS.format(Instant.now())).append("</span></footer>");
        h.append("</body></html>");
        return h.toString();
    }

    private static void renderFinding(StringBuilder h, String id, FindingGroup g, ReportOptions opt, Evidence evidence) {
        String sev = g.severity.toUpperCase(Locale.ROOT);
        String sevCls = sev.toLowerCase(Locale.ROOT);
        h.append("<article class=\"finding sev-").append(sevCls).append("\" id=\"").append(id).append("\">")
         .append("<header class=\"fhead\"><div class=\"fid\">").append(id).append("</div>")
         .append("<div class=\"ftitle\"><h3>").append(esc(g.title)).append("</h3>")
         .append("<div class=\"fpills\"><span class=\"pill sev-").append(sevCls).append("\">").append(cap(sev)).append("</span>")
         .append(cvssPill(g.score()))
         .append("<span class=\"pill ghost\">Confidence: ").append(cap(g.confidence)).append("</span>")
         .append("<span class=\"pill ghost\">").append(Math.max(1, g.urls.size())).append(g.urls.size() == 1 ? " location" : " locations").append("</span>")
         .append(triagePill(g.aiTriage)).append("</div></div></header>");

        h.append("<div class=\"fgrid\">");
        block(h, "Affected URLs", urlList(g));
        block(h, "Issue description", "<p>" + para(g.detail) + "</p>");
        Cvss.Score cv = g.score();
        block(h, "CVSS v3.1 base score (estimate)", cv.vector().isEmpty()
                ? "<p class=\"muted\">Informational; not scored.</p>"
                : "<p><strong>" + String.format(Locale.ROOT, "%.1f", cv.base()) + " (" + cv.rating() + ")</strong> &middot; <code>"
                  + esc(cv.vector()) + "</code></p><p class=\"muted small\">Suggested from the finding category and kept consistent with the reported "
                  + "severity. Re-score against the confirmed impact before relying on it.</p>");
        RemediationKb.Entry kb = RemediationKb.lookup(g.title, g.detail);
        block(h, "Impact", "<p>" + para(kb.impact()) + "</p>");
        if (g.aiTriage != null && !g.aiTriage.isBlank())
            block(h, "AI false-positive analysis", "<p class=\"triage-text\">" + esc(g.aiTriage) + "</p>");
        h.append("</div>");

        // Proof of concept: one anchored block per evidence reference. The references in the Evidence line link here.
        h.append("<div class=\"subhead\">Proof of concept</div>");
        Set<String> rendered = new LinkedHashSet<>();
        if (opt.includeEvidence && evidence != null && !g.evidence.isEmpty()) {
            for (String ref : g.evidence) {
                if (rendered.size() >= MAX_POC) break;
                HttpRequestResponse rr = resolve(evidence, ref, g.urls);
                if (rr == null) continue;
                rendered.add(ref);
                h.append("<div class=\"poc-block\" id=\"").append(pocId(id, ref)).append("\">")
                 .append("<div class=\"poc-meta\"><span>Reference</span><code class=\"ref\">").append(esc(ref)).append("</code>")
                 .append("<span>").append(esc(sourceOf(ref))).append("</span>");
                if (rr.hasResponse()) h.append("<span>Response</span><strong>HTTP ").append(rr.response().statusCode()).append("</strong>");
                h.append("</div><pre class=\"poc\">").append(esc(Fmt.request(rr.request(), 2000, true))).append("</pre>");
                if (rr.hasResponse())
                    h.append("<details class=\"respwrap\"><summary>Response excerpt (first 800 bytes)</summary><pre class=\"poc\">")
                     .append(esc(Fmt.response(rr.response(), 800, true))).append("</pre></details>");
                h.append("</div>");
            }
            if (g.evidence.size() > rendered.size())
                h.append("<p class=\"muted small\">Showing ").append(rendered.size()).append(" of ").append(g.evidence.size())
                 .append(" captured request(s) here; the others are in the Excel export's Evidence sheet or Burp's Proxy history.</p>");
        }
        if (rendered.isEmpty())
            h.append("<p class=\"muted small\">Reproduce from the description and the affected URL(s) using Burp's Proxy history or Repeater.</p>");

        h.append("<div class=\"subhead\">Remediation</div><div class=\"remediation\">");
        if (!g.remediation.isBlank())
            h.append("<p class=\"finding-specific\"><strong>Specific to this finding:</strong> ").append(esc(g.remediation)).append("</p>");
        h.append("<p>").append(para(kb.remediation())).append("</p>");
        if (!kb.refs().isEmpty()) {
            h.append("<div class=\"refs-title\">References</div><ol class=\"refs\">");
            for (RemediationKb.Ref ref : kb.refs())
                h.append("<li><a href=\"").append(esc(ref.url())).append("\" target=\"_blank\" rel=\"noopener\">")
                 .append(esc(ref.title())).append("</a><span class=\"refurl\">").append(esc(ref.url())).append("</span></li>");
            h.append("</ol>");
        }
        h.append("</div>");

        if (opt.includeEvidence && !g.evidence.isEmpty()) {
            h.append("<div class=\"evidence-line\"><span>Evidence</span> ");
            for (String ref : g.evidence) {
                if (rendered.contains(ref))
                    h.append("<a class=\"ref-link\" href=\"#").append(pocId(id, ref)).append("\"><code>").append(esc(ref)).append("</code></a> ");
                else
                    h.append("<code>").append(esc(ref)).append("</code> ");
            }
            h.append("<div class=\"legend\">p = Proxy history item &middot; a = request sent by the agent &middot; s = request selected by the tester. "
                    + "Linked references jump to the captured request in the proof of concept.</div></div>");
        }
        h.append("<div class=\"recorded\">Recorded ").append(TS.format(Instant.ofEpochMilli(g.time))).append("</div>");
        h.append("</article>");
    }

    /** Anchor id of a proof-of-concept block: unique per finding and per reference. */
    static String pocId(String fid, String ref) { return fid + "-poc-" + (ref == null ? "" : ref.replaceAll("[^A-Za-z0-9_-]", "")); }

    /** What a reference prefix means: p = Proxy history, a = sent by the agent, s = selected by the tester. */
    static String sourceOf(String ref) {
        String r = ref == null ? "" : ref.trim().toLowerCase(Locale.ROOT);
        if (r.startsWith("p")) return "Proxy history";
        if (r.startsWith("a")) return "Agent-sent";
        if (r.startsWith("s")) return "Selected";
        return "Other";
    }

    private static String urlList(FindingGroup g) {
        if (g.urls.isEmpty()) return "<p class=\"muted\">Not recorded.</p>";
        StringBuilder b = new StringBuilder("<ul class=\"urls\">");
        for (String u : g.urls) b.append("<li><code>").append(esc(u)).append("</code></li>");
        return b.append("</ul>").toString();
    }

    private static void block(StringBuilder h, String label, String html) {
        h.append("<div class=\"fblock\"><div class=\"flabel\">").append(esc(label)).append("</div>").append(html).append("</div>");
    }

    private static String cvssPill(Cvss.Score s) {
        if (s.vector().isEmpty()) return "<span class=\"pill ghost\">Not scored</span>";
        return "<span class=\"pill cvss\">CVSS " + String.format(Locale.ROOT, "%.1f", s.base()) + " &middot; " + s.rating() + "</span>";
    }

    private static String cvssCell(Cvss.Score s) {
        if (s.vector().isEmpty()) return "<span class=\"muted\">n/a</span>";
        return "<strong>" + String.format(Locale.ROOT, "%.1f", s.base()) + "</strong><br><span class=\"muted small\">" + s.rating() + "</span>";
    }

    private static String share(long part, long total) {
        return total == 0 ? "0%" : Math.round(100.0 * part / total) + "%";
    }

    private static String severityBreakdown(Map<String, Long> counts) {
        return "By reported severity: " + counts.get("HIGH") + " high, " + counts.get("MEDIUM") + " medium, "
                + counts.get("LOW") + " low and " + counts.get("INFORMATION") + " informational.";
    }

    private static String triageLabel(String t) {
        if (t == null || t.isBlank()) return "<span class=\"muted\">Not analysed</span>";
        return triagePill(t);
    }

    private static String triagePill(String t) {
        if (t == null || t.isBlank()) return "";
        String u = t.toUpperCase(Locale.ROOT);
        String cls = u.startsWith("FALSE") ? "fp" : u.startsWith("TRUE") ? "tp" : "rev";
        String label = u.startsWith("FALSE") ? "AI: false positive" : u.startsWith("TRUE") ? "AI: true positive" : "AI: needs review";
        return "<span class=\"pill triage-" + cls + "\">" + label + "</span>";
    }

    private static String fid(int i) { return String.format(Locale.ROOT, "f-%03d", i + 1); }

    private static void fact(StringBuilder h, String k, String v) {
        h.append("<div><dt>").append(k).append("</dt><dd>").append(v).append("</dd></div>");
    }

    private static HttpRequestResponse resolve(Evidence evidence, String ref, java.util.Collection<String> urls) {
        return evidence.forFinding(ref, urls);
    }

    private static String cap(String s) { return s == null || s.isEmpty() ? "" : s.charAt(0) + s.substring(1).toLowerCase(Locale.ROOT); }
    private static String para(String s) { return esc(s).replace("\n", "<br>"); }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static final String CSS = """
        @page{size:A4;margin:16mm 14mm}
        :root{--ink:#16202e;--ink2:#3a4658;--muted:#6b7689;--line:#dfe4ec;--paper:#ffffff;--wash:#f5f7fa;
          --navy:#0d2238;--teal:#0f7b80;
          --high:#b42318;--high-bg:#fdecea;--med:#b54708;--med-bg:#fef3e2;--low:#175cd3;--low-bg:#e8f0fd;--info:#475467;--info-bg:#eef1f5;}
        *{box-sizing:border-box}
        html{color-scheme:light}
        body{margin:0;background:var(--wash);color:var(--ink);font:14.5px/1.6 "Segoe UI",system-ui,-apple-system,Helvetica,Arial,sans-serif}
        h1,h2,h3{font-family:Georgia,"Times New Roman",serif;font-weight:700;color:var(--navy);margin:0}
        code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
        code{background:#eef2f7;color:var(--ink);padding:1px 6px;border-radius:4px;font-size:12.5px;word-break:break-all}
        a{color:var(--teal);text-decoration:none} a:hover{text-decoration:underline}
        .muted{color:var(--muted)} .small{font-size:12.5px}

        /* cover */
        header.cover{background:var(--navy);color:#e9eef5;padding:64px 56px 48px;position:relative;border-bottom:6px solid var(--teal)}
        header.cover:before{content:"";position:absolute;inset:0;background:repeating-linear-gradient(135deg,rgba(255,255,255,.035) 0 2px,transparent 2px 22px);pointer-events:none}
        .cover-inner{position:relative;max-width:920px;margin:0 auto}
        .kicker{letter-spacing:.18em;text-transform:uppercase;font-size:12px;color:#8fd3d6;font-weight:600}
        header.cover h1{color:#fff;font-size:38px;line-height:1.15;margin:14px 0 10px}
        .cover-sub{color:#b9c6d6;font-size:16px;margin-bottom:28px}
        dl.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px 32px;margin:0;padding:22px 0;border-top:1px solid rgba(255,255,255,.18)}
        dl.facts dt{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#8fa3bb}
        dl.facts dd{margin:2px 0 0;font-size:15px;color:#fff}
        .classification{margin-top:22px;font-size:11.5px;letter-spacing:.08em;color:#f3c5c0;border:1px solid rgba(243,197,192,.4);display:inline-block;padding:6px 12px;border-radius:4px}

        /* layout */
        main{max-width:960px;margin:0 auto;padding:8px 40px 40px}
        main>section{background:var(--paper);border:1px solid var(--line);border-radius:12px;padding:28px 32px;margin:22px 0;box-shadow:0 1px 2px rgba(13,34,56,.04)}
        main h2{font-size:22px;display:flex;align-items:center;gap:12px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--line)}
        .num{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:50%;background:var(--navy);color:#fff;font:700 14px/1 system-ui,sans-serif;flex:none}
        p{margin:0 0 10px} .lede{font-size:16px;color:var(--ink2)}
        .caveat{margin-top:18px;padding:12px 14px;background:var(--wash);border-left:3px solid var(--teal);border-radius:4px;font-size:13px;color:var(--ink2)}

        /* severity bars */
        .bars{margin:18px 0 4px;display:grid;gap:10px}
        .bar-row{display:grid;grid-template-columns:110px 1fr 48px;align-items:center;gap:12px}
        .bar-label{font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase}
        .bar-track{height:14px;background:var(--wash);border:1px solid var(--line);border-radius:999px;overflow:hidden;display:block}
        .bar-fill{display:block;height:100%;border-radius:999px}
        .bar-count{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
        .sev-high{color:var(--high)} .sev-medium{color:var(--med)} .sev-low{color:var(--low)} .sev-information{color:var(--info)}
        .bar-fill.sev-high{background:var(--high)} .bar-fill.sev-medium{background:var(--med)} .bar-fill.sev-low{background:var(--low)} .bar-fill.sev-information{background:var(--info)}

        /* pills */
        .pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap;border:1px solid transparent}
        .pill.sev-high{background:var(--high);color:#fff} .pill.sev-medium{background:var(--med);color:#fff}
        .pill.sev-low{background:var(--low);color:#fff} .pill.sev-information{background:var(--info);color:#fff}
        .pill.ghost{background:var(--wash);color:var(--ink2);border-color:var(--line)}
        .pill.triage-fp{background:#fdecea;color:var(--high);border-color:#f7c4bd}
        .pill.triage-tp{background:#e8f0fd;color:var(--low);border-color:#c3d6f8}
        .pill.triage-rev{background:#fef3e2;color:var(--med);border-color:#f6d9ac}

        /* index table */
        table{width:100%;border-collapse:collapse;font-size:13.5px}
        th{text-align:left;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:700;padding:9px 10px;border-bottom:2px solid var(--line)}
        td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
        tr:last-child td{border-bottom:0}
        .c-id{width:84px;font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:600}
        .c-sev{width:120px} .c-n{width:90px;text-align:center} .c-ai{width:200px}
        .index-table td a{color:var(--navy);font-weight:600}
        .c-cv{width:120px;white-space:nowrap}
        table.mgmt{margin-bottom:6px} table.mgmt tr.total td{font-weight:600;border-top:2px solid var(--line)}
        .subtle-title{font:700 11px/1 system-ui,sans-serif;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:18px 0 8px}
        ol.top-risks{margin:0 0 12px;padding-left:20px} ol.top-risks li{margin:0 0 4px}
        .pill.cvss{background:#fff;color:var(--navy);border-color:var(--navy)}

        /* finding article */
        article.finding{border:1px solid var(--line);border-radius:10px;margin:0 0 22px;overflow:hidden;background:var(--paper);break-inside:avoid-page}
        article.finding{border-top:4px solid var(--info)}
        article.finding.sev-high{border-top-color:var(--high)} article.finding.sev-medium{border-top-color:var(--med)}
        article.finding.sev-low{border-top-color:var(--low)}
        .fhead{display:flex;gap:16px;padding:18px 22px;background:var(--wash);border-bottom:1px solid var(--line)}
        .fid{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;font-weight:700;color:var(--muted);padding-top:4px;flex:none}
        .ftitle{min-width:0} .ftitle h3{font-size:18px;line-height:1.3}
        .fpills{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
        .fgrid{display:grid;grid-template-columns:1fr;gap:0;padding:4px 22px}
        .fblock{padding:14px 0;border-bottom:1px dashed var(--line)} .fblock:last-child{border-bottom:0}
        .flabel{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:700;margin-bottom:6px}
        ul.urls{margin:0;padding:0;list-style:none;display:grid;gap:6px}
        ul.urls li code{display:block}
        .triage-text{font-size:13.5px;color:var(--ink2)}
        .subhead{font:700 12px/1 system-ui,sans-serif;letter-spacing:.12em;text-transform:uppercase;color:var(--teal);padding:18px 22px 0}
        .poc-meta{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;font-size:12.5px;color:var(--muted);margin:12px 22px 6px}
        .poc-meta .ref{color:var(--ink)}
        pre.poc{font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;background:#0f1a27;color:#dbe6f3;border-radius:8px;padding:12px 14px;margin:0 22px 10px;overflow-x:auto}
        details.respwrap{margin:0 22px 10px} details.respwrap>summary{cursor:pointer;color:var(--muted);font-size:12.5px;padding:4px 0}
        details.respwrap pre.poc{margin:6px 0 0}
        .remediation{padding:4px 22px 8px}
        .finding-specific{background:var(--wash);border-left:3px solid var(--teal);padding:10px 12px;border-radius:4px;margin:8px 0 12px}
        .refs-title{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:700;margin:12px 0 6px}
        ol.refs{margin:0;padding-left:20px} ol.refs li{margin:0 0 6px}
        .refurl{display:block;color:var(--muted);font-size:12px;word-break:break-all}
        .evidence-line{padding:12px 22px;border-top:1px dashed var(--line);font-size:12.5px;color:var(--muted)}
        .evidence-line span{font-weight:700;letter-spacing:.06em;text-transform:uppercase;font-size:11px;margin-right:6px}
        a.ref-link{text-decoration:none} a.ref-link code{color:var(--teal);border:1px solid var(--teal);background:#fff}
        a.ref-link:hover code{background:var(--teal);color:#fff}
        .legend{margin-top:6px;font-size:12px;color:var(--muted)}
        .poc-block{scroll-margin-top:16px;border-radius:10px;padding-bottom:2px} .poc-block:target{outline:2px solid var(--teal);outline-offset:4px}
        .logo{display:block;max-height:64px;max-width:240px;background:#fff;padding:8px 12px;border-radius:8px;margin:0 0 18px}
        .org{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:#cfe3ee;margin-bottom:6px;font-weight:600}
        .recorded{padding:8px 22px 14px;font-size:12px;color:var(--muted)}

        /* appendix tables */
        table.audit td{font-size:12.5px} table.audit{font-size:12.5px}
        .tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11.5px;border:1px solid var(--line);color:var(--muted)}
        .tag-allowed{color:#1a7f37} .tag-blocked,.tag-denied{color:var(--high)} .tag-invalid{color:var(--med)}

        footer{max-width:960px;margin:0 auto;padding:18px 40px 40px;display:flex;justify-content:space-between;gap:16px;font-size:12px;color:var(--muted);flex-wrap:wrap}

        @media (max-width:700px){ header.cover{padding:40px 22px} dl.facts{grid-template-columns:1fr} main{padding:8px 12px} main>section{padding:20px} .fhead{flex-direction:column;gap:6px} }
        @media print{
          body{background:#fff} header.cover{-webkit-print-color-adjust:exact;print-color-adjust:exact}
          main>section{box-shadow:none;border-color:#ccd3dd;page-break-inside:auto}
          main h2{break-after:avoid} article.finding{break-inside:avoid-page}
          pre.poc{-webkit-print-color-adjust:exact;print-color-adjust:exact}
          details.respwrap{display:block} details.respwrap>summary{display:none}
          details.respwrap>pre{display:block}
          a{color:var(--ink)}
        }
        """;
}
