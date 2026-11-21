package ollamaat.agent;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Human-in-the-loop queue. The agent thread blocks here until the pentester answers (or it times out = deny). */
public final class Approvals {
    public enum Answer { ALLOW_ONCE, ALLOW_RUN, DENY, DENY_STOP, TIMEOUT }

    public static final class Request {
        public final int id;
        public final int runId;
        public final String tool, summary, detail, reason;
        public final long created = System.currentTimeMillis();
        final CompletableFuture<Answer> future = new CompletableFuture<>();
        Request(int id, int runId, String tool, String summary, String detail, String reason) {
            this.id = id; this.runId = runId; this.tool = tool; this.summary = summary; this.detail = detail; this.reason = reason;
        }
        @Override public String toString() { return "#" + id + "  " + tool + "  " + summary; }
    }

    private final AtomicInteger seq = new AtomicInteger();
    private final List<Request> pending = new CopyOnWriteArrayList<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public void onChange(Runnable r) { listeners.add(r); }
    private void fire() { for (Runnable r : listeners) try { r.run(); } catch (RuntimeException ignored) { } }

    public List<Request> pending() { return new ArrayList<>(pending); }

    /** Blocks the calling (agent) thread. */
    public Answer request(int runId, String tool, String summary, String detail, String reason, int timeoutSec) {
        Request r = new Request(seq.incrementAndGet(), runId, tool, summary, detail, reason);
        pending.add(r);
        fire();
        try {
            return r.future.get(Math.max(1, timeoutSec), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            return Answer.TIMEOUT;
        } catch (InterruptedException | ExecutionException e) {
            Thread.currentThread().interrupt();
            return Answer.DENY_STOP;
        } finally {
            pending.remove(r);
            fire();
        }
    }

    public void answer(Request r, Answer a) { r.future.complete(a); }

    /** Denies everything outstanding for a run (used on Stop). */
    public void cancelRun(int runId) {
        for (Request r : pending) if (r.runId == runId) r.future.complete(Answer.DENY_STOP);
    }
}
