package ollamaat.agent;

import ollamaat.Settings;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Deterministic control layer, deliberately separate from the model. The model can only propose actions;
 * this class (plus the human) decides. Nothing here is prompt-based, so it cannot be talked around.
 */
public final class Policy {
    public enum Verdict { ALLOW, ASK, BLOCK }
    public record Decision(Verdict verdict, String reason) {
        static Decision allow(String r) { return new Decision(Verdict.ALLOW, r); }
        static Decision ask(String r) { return new Decision(Verdict.ASK, r); }
        static Decision block(String r) { return new Decision(Verdict.BLOCK, r); }
    }

    private static final Pattern DESTRUCTIVE = Pattern.compile(
            "(?i)(delete|remove|destroy|drop|purge|wipe|revoke|cancel|terminate|disable|unsubscribe|"
                    + "checkout|purchase|payment|pay|transfer|withdraw|refund|reset|logout|signout|sign-out|log-out)");

    private final Settings settings;
    private final Predicate<String> inScope;

    public Policy(Settings settings, Predicate<String> inScope) {
        this.settings = settings;
        this.inScope = inScope;
    }

    public static String allowanceKey(String tool, Action.NetInfo n) {
        String host = "";
        try { host = URI.create(n.url()).getHost(); } catch (RuntimeException e) { /* ignore */ }
        return tool + "|" + n.method().toUpperCase() + "|" + host;
    }

    public Decision evaluate(String tool, Action a, RunState rs) {
        switch (a.kind()) {
            case READ:
            case FINISH:
                return Decision.allow("read-only");
            case ANNOTATE:
                return Decision.allow("local annotation (findings/notes)");
            case PROJECT_WRITE:
                return settings.autonomy() == Settings.Autonomy.STRICT
                        ? Decision.ask("strict mode: project changes need approval")
                        : Decision.allow("project annotation");
            case NETWORK:
                return network(tool, a, rs);
            default:
                return Decision.block("unknown action kind");
        }
    }

    private Decision network(String tool, Action a, RunState rs) {
        Action.NetInfo n = a.net();
        if (n == null) return Decision.block("network action without request details");
        if (!rs.allowNetwork) return Decision.block("this run is read-only (no network access)");

        String url = n.url();
        URI u;
        try { u = URI.create(url); } catch (RuntimeException e) { return Decision.block("invalid URL"); }
        if (u.getHost() == null || !(url.startsWith("http://") || url.startsWith("https://")))
            return Decision.block("only absolute http(s) URLs are allowed");

        // 1. Hard scope gate: Burp's target scope is the only source of truth.
        if (!inScope.test(url))
            return Decision.block("out of Burp target scope (" + u.getHost() + "). Add the target to Burp scope to test it");

        // 2. Hard budget gate.
        if (rs.requestsSent.get() >= settings.maxRequestsPerRun())
            return Decision.block("request budget exhausted (" + settings.maxRequestsPerRun() + " per run)");

        // 3. User-defined hard block list.
        for (String line : settings.blockedPatterns().split("\\n")) {
            String p = line.trim();
            if (p.isEmpty()) continue;
            try { if (Pattern.compile(p).matcher(url).find()) return Decision.block("matches blocked pattern: " + p); }
            catch (PatternSyntaxException e) { /* ignore bad user regex */ }
        }

        String method = n.method().toUpperCase();
        boolean safeMethod = method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS");
        boolean destructive = method.equals("DELETE") || DESTRUCTIVE.matcher(urlPathAndQuery(u)).find();

        // 4. Things a human must always see.
        if (method.equals("DELETE")) return Decision.ask("DELETE requests always require approval");
        if (destructive) return Decision.ask("URL looks state-changing/destructive");

        // 5. Per-run allowance the user granted earlier.
        if (rs.allowances.contains(allowanceKey(tool, n))) return Decision.allow("approved earlier for this run");

        switch (settings.autonomy()) {
            case STRICT:
                return Decision.ask("strict mode: every request needs approval");
            case SMART:
                if (safeMethod && !n.hasBody()) return Decision.allow("in-scope read-only request");
                return Decision.ask(method + " may change server state");
            case AUTONOMOUS:
                return Decision.allow("autonomous mode, in scope");
            default:
                return Decision.ask("unknown autonomy level");
        }
    }

    private static String urlPathAndQuery(URI u) {
        return (u.getPath() == null ? "" : u.getPath()) + "?" + (u.getQuery() == null ? "" : u.getQuery());
    }

    public static List<String> validatePatterns(String text) {
        List<String> bad = new ArrayList<>();
        for (String l : text.split("\\n")) {
            if (l.isBlank()) continue;
            try { Pattern.compile(l.trim()); } catch (PatternSyntaxException e) { bad.add(l.trim()); }
        }
        return bad;
    }
}
