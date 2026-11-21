package ollamaat.agent;

import java.util.concurrent.Callable;

/** What a tool call would do. NetInfo is non-null for anything that sends traffic to a target. */
public record Action(Kind kind, String summary, NetInfo net, Callable<String> exec) {
    public enum Kind { READ, PROJECT_WRITE, NETWORK, FINISH, ANNOTATE }

    /** Burp-independent description of an outgoing request, for policy checks and approval dialogs. */
    public record NetInfo(String method, String url, boolean hasBody, String raw) {}

    public static Action read(String summary, Callable<String> exec) { return new Action(Kind.READ, summary, null, exec); }
    public static Action write(String summary, Callable<String> exec) { return new Action(Kind.PROJECT_WRITE, summary, null, exec); }
    /** A local annotation of AuditLens's own project data (findings list, notes). Always allowed: it records no traffic
     *  and cannot change the target, so it is never gated behind approval and never silently dropped. */
    public static Action annotate(String summary, Callable<String> exec) { return new Action(Kind.ANNOTATE, summary, null, exec); }
    public static Action network(String summary, NetInfo net, Callable<String> exec) { return new Action(Kind.NETWORK, summary, net, exec); }
    public static Action finish(String summary) { return new Action(Kind.FINISH, summary, null, () -> summary); }
}
