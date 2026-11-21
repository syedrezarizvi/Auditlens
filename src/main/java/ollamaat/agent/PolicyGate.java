package ollamaat.agent;

import ollamaat.Settings;

/**
 * Shared "evaluate -> maybe ask -> maybe block -> record audit" pipeline. Used by both the chat {@link Agent}
 * and the deterministic {@link ollamaat.scan.ActiveScanEngine}, so a probe sent by the scanner is gated by
 * exactly the same scope/approval/budget/block-list rules as one proposed by the model.
 */
public final class PolicyGate {
    public static final class Outcome {
        public final boolean allowed;
        public final String decidedBy;
        public final String message;
        public final boolean stopRun;
        Outcome(boolean allowed, String decidedBy, String message, boolean stopRun) {
            this.allowed = allowed; this.decidedBy = decidedBy; this.message = message; this.stopRun = stopRun;
        }
    }

    private final Settings settings;
    private final Policy policy;
    private final Approvals approvals;
    private final AuditLog audit;

    public PolicyGate(Settings settings, Policy policy, Approvals approvals, AuditLog audit) {
        this.settings = settings; this.policy = policy; this.approvals = approvals; this.audit = audit;
    }

    /** Evaluates the action; if approval is needed, blocks the calling thread until the pentester answers. */
    public Outcome check(String tool, Action a, RunState rs) {
        Policy.Decision d = policy.evaluate(tool, a, rs);

        if (d.verdict() == Policy.Verdict.BLOCK) {
            audit.add(rs.runId, tool, a.summary(), "BLOCKED", "policy", d.reason());
            return new Outcome(false, "policy", d.reason(), false);
        }
        if (d.verdict() != Policy.Verdict.ASK) return new Outcome(true, "policy", d.reason(), false);

        Approvals.Answer ans = approvals.request(rs.runId, tool, a.summary(),
                a.net() != null ? a.net().raw() : a.summary(), d.reason(), settings.approvalTimeoutSec());
        String by = ans == Approvals.Answer.TIMEOUT ? "timeout" : "user";
        switch (ans) {
            case ALLOW_ONCE:
                return new Outcome(true, by, d.reason(), false);
            case ALLOW_RUN:
                if (a.net() != null) rs.allowances.add(Policy.allowanceKey(tool, a.net()));
                return new Outcome(true, by, d.reason(), false);
            case DENY_STOP:
                rs.cancelled = true;
                audit.add(rs.runId, tool, a.summary(), "DENIED", by, "run stopped by user");
                return new Outcome(false, by, "the pentester stopped this run", true);
            default:
                audit.add(rs.runId, tool, a.summary(), "DENIED", by, ans == Approvals.Answer.TIMEOUT ? "approval timed out" : "denied by user");
                return new Outcome(false, by, ans == Approvals.Answer.TIMEOUT ? "approval timed out" : "denied by the pentester", false);
        }
    }

    public void recordAllowed(int runId, String tool, String summary, String decidedBy, String outcome) {
        audit.add(runId, tool, summary, "ALLOWED", decidedBy, outcome);
    }

    public void recordInvalid(int runId, String tool, String summary, String message) {
        audit.add(runId, tool, summary, "INVALID", "tool", message);
    }
}
